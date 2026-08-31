"""Shared fixtures. No AWS credentials and no PRTG server are required."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

#: A passhash-shaped value. Tests assert this string never appears in anything
#: returned to the caller or written to a log.
FAKE_PASSHASH = "1234567890abcdef"
FAKE_USERNAME = "prtg-readonly-svc"
FAKE_URL = "https://prtg.example.internal"


class FakeSecretsClient:
    """Minimal stand-in for the Secrets Manager client."""

    def __init__(self, payloads: dict[str, str] | None = None, *, fail_with: Exception | None = None) -> None:
        self.payloads = payloads or {}
        self.fail_with = fail_with
        self.call_count = 0

    def get_secret_value(self, *, SecretId: str) -> dict[str, str]:  # noqa: N803 - boto3 casing
        self.call_count += 1
        if self.fail_with is not None:
            raise self.fail_with
        if SecretId not in self.payloads:
            raise KeyError(f"No such fake secret: {SecretId}")
        return {"SecretString": self.payloads[SecretId]}


class FakeResponse:
    """Stand-in for a urllib3 HTTPResponse."""

    def __init__(self, status: int = 200, body: Any = None, content_type: str = "application/json") -> None:
        self.status = status
        if isinstance(body, (dict, list)):  # noqa: SIM108 - a nested ternary reads worse here
            raw = json.dumps(body)
        else:
            raw = "" if body is None else str(body)
        self.data = raw.encode("utf-8")
        self.headers = {"content-type": content_type}


class FakePool:
    """Records requests and returns queued responses, or raises a queued error."""

    def __init__(self, responses: list[Any] | None = None, *, raises: Exception | None = None) -> None:
        self.responses = list(responses or [])
        self.raises = raises
        self.requests: list[dict[str, Any]] = []

    def request(self, method: str, url: str, *, fields: Any = None, **kwargs: Any) -> Any:
        # Kept as the client passed them. urllib3 accepts a mapping or a sequence of
        # pairs, and the difference is not cosmetic: PRTG expresses a multi-valued
        # filter by repeating a key, which a mapping cannot represent. Recording only
        # a dict view here is what let the indexed filter_status[0] bug reach a real
        # server -- the assertion could not see the shape that mattered.
        pairs: list[tuple[str, Any]] = (
            list(fields.items()) if isinstance(fields, Mapping) else list(fields or [])
        )
        self.requests.append({"method": method, "url": url, "pairs": pairs, "kwargs": kwargs})
        if self.raises is not None:
            raise self.raises
        if not self.responses:
            return FakeResponse(200, {})
        return self.responses.pop(0)

    @property
    def last_pairs(self) -> list[tuple[str, Any]]:
        """Every parameter as sent, duplicates preserved."""
        return self.requests[-1]["pairs"]

    @property
    def last_fields(self) -> dict[str, Any]:
        """Convenience view for single-valued parameters. Last value wins.

        Use ``last_pairs`` when a key may legitimately repeat.
        """
        return dict(self.requests[-1]["pairs"])


@pytest.fixture(autouse=True)
def _isolate_prtg_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear ``PRTG_*`` variables so the suite cannot read the developer's shell.

    The client falls back to environment variables for its URL, credential and TLS
    setting, so anyone who had exported ``PRTG_VERIFY_TLS=false`` to talk to a real
    server saw ``test_verification_is_enabled_by_default`` fail with no code change --
    and, worse, could have seen it pass for the wrong reason. Tests that want a
    variable set still set it themselves with ``monkeypatch.setenv``.
    """
    for name in (
        "PRTG_URL",
        "PRTG_USERNAME",
        "PRTG_PASSHASH",
        "PRTG_VERIFY_TLS",
        "PRTG_SECRET_ARN",
        "PRTG_CA_BUNDLE_SECRET_ARN",
        # Decides whether the environment credential fallback is refused, so a stray
        # value would change behaviour rather than merely a setting.
        "AWS_LAMBDA_FUNCTION_NAME",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def credential_json() -> str:
    return json.dumps({"prtg_url": FAKE_URL, "prtg_username": FAKE_USERNAME, "prtg_passhash": FAKE_PASSHASH})


@pytest.fixture
def secrets_client(credential_json: str) -> FakeSecretsClient:
    return FakeSecretsClient({"prtg-secret": credential_json})


@pytest.fixture
def client(secrets_client: FakeSecretsClient):
    """A PrtgClient wired to fakes, with TLS verification on."""
    from prtg_mcp.prtg_client import PrtgClient

    return PrtgClient(
        secret_arn="prtg-secret",
        verify_tls=True,
        secrets_client=secrets_client,
        credential_ttl_seconds=900,
    )


class FakeClientContext:
    def __init__(self, tool_name: str | None) -> None:
        self.custom = {"bedrockAgentCoreToolName": tool_name} if tool_name is not None else {}


class FakeLambdaContext:
    """Stand-in for the Lambda context object.

    The tool name arrives here rather than in the event, which is the part of the
    AgentCore Gateway contract that most often trips people up.
    """

    def __init__(self, tool_name: str | None = None, *, with_client_context: bool = True) -> None:
        self.client_context = FakeClientContext(tool_name) if with_client_context else None
        self.aws_request_id = "test-request-id"


@pytest.fixture
def lambda_context():
    return FakeLambdaContext
