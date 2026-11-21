"""Local configuration and signed test delivery for HTTPS webhooks."""

import hashlib
import hmac
import json
import socket
import ssl
from datetime import UTC, datetime
from http.client import HTTPException as ClientError
from http.client import HTTPSConnection
from ipaddress import ip_address
from typing import Annotated
from urllib.parse import SplitResult, urlsplit

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.repository import Repository


class WebhookInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    url: Annotated[str, Field(min_length=9, max_length=512)]


class WebhookStatus(BaseModel):
    url: str | None
    secret_configured: bool


class Delivery(BaseModel):
    status: int
    delivered: bool
    sent_at: datetime


class UnsafeDestination(ValueError):
    pass


def resolve_destination(url: str) -> tuple[SplitResult, str]:
    parsed = urlsplit(url)
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or not host
        or parsed.port not in {None, 443}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not host.isascii()
        or any(char.isspace() for char in url)
        or "\\" in url
    ):
        raise UnsafeDestination(
            "Use an HTTPS endpoint on port 443 without URL credentials, query or fragment"
        )
    addresses = sorted(
        {
            str(row[4][0])
            for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        }
    )
    if not addresses or any(
        not (address := ip_address(value)).is_global or address.is_multicast
        for value in addresses
    ):
        raise UnsafeDestination(
            "The destination must resolve exclusively to public addresses"
        )
    return parsed, addresses[0]


class PinnedHTTPS(HTTPSConnection):
    def __init__(self, hostname: str, address: str) -> None:
        self.tls_context = ssl.create_default_context()
        super().__init__(hostname, port=443, timeout=6, context=self.tls_context)
        self.address = address

    def connect(self) -> None:
        raw = socket.create_connection((self.address, 443), timeout=self.timeout)
        try:
            self.sock = self.tls_context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def send_test(url: str, secret: str, now: datetime) -> int:
    destination, address = resolve_destination(url)
    if destination.hostname is None:
        raise UnsafeDestination("The destination has no hostname")
    body = json.dumps(
        {"event": "identityguard.webhook.test", "at": now.isoformat()},
        separators=(",", ":"),
    ).encode()
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    connection = PinnedHTTPS(destination.hostname, address)
    try:
        connection.request(
            "POST",
            destination.path or "/",
            body,
            {
                "Content-Type": "application/json",
                "X-IdentityGuard-Signature": f"sha256={signature}",
            },
        )
        return connection.getresponse().status
    finally:
        connection.close()


def router_for(repository: Repository, secret: str | None) -> APIRouter:
    router = APIRouter()

    @router.get("/integrations/webhook", operation_id="getWebhookStatus")
    def status() -> WebhookStatus:
        saved = repository.read_setting("webhook") or {}
        return WebhookStatus(url=saved.get("url"), secret_configured=bool(secret))

    @router.put("/integrations/webhook", operation_id="saveWebhook")
    def save(body: WebhookInput) -> WebhookStatus:
        try:
            resolve_destination(body.url)
        except (ValueError, OSError) as error:
            raise HTTPException(
                422, "The webhook must resolve to a public HTTPS endpoint"
            ) from error
        repository.save_setting("webhook", body.model_dump(), "webhook.configured")
        return status()

    @router.post("/integrations/webhook/test", operation_id="testWebhook")
    def test() -> Delivery:
        saved = status()
        if not secret or not saved.url:
            raise HTTPException(
                409, "Configure an endpoint and IG_WEBHOOK_SECRET first"
            )
        now = datetime.now(UTC)
        try:
            code = send_test(saved.url, secret, now)
        except (ValueError, OSError, ClientError):
            repository.record_action("webhook.test.failed", repository.source, {})
            raise HTTPException(502, "Webhook delivery failed") from None
        repository.record_action(
            "webhook.test.completed", repository.source, {"status": code}
        )
        return Delivery(status=code, delivered=200 <= code < 300, sent_at=now)

    return router
