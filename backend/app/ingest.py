import gzip
import io
import json
import re
import zlib
from datetime import UTC, datetime
from typing import Any

from app.engine.events import Event, Identity

MAX_UPLOAD = 20 * 1024 * 1024
MAX_UNPACKED = 100 * 1024 * 1024
ACCOUNT = re.compile(r"[0-9]{12}")


class InvalidCloudTrail(ValueError):
    pass


def obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def field(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    return value if isinstance(value, str) else ""


def bool_value(value: Any) -> bool | None:
    if value is True or isinstance(value, str) and value.lower() in {"true", "yes"}:
        return True
    if value is False or isinstance(value, str) and value.lower() in {"false", "no"}:
        return False
    return None


def attribute(record: dict[str, Any], account_id: str) -> tuple[Identity | None, str]:
    data = obj(record.get("userIdentity"))
    kind = field(data, "type")
    actor_account = field(data, "accountId")
    if not ACCOUNT.fullmatch(actor_account):
        actor_account = account_id
    name = field(data, "userName")
    session = ""
    if kind == "AssumedRole":
        issuer = obj(obj(data.get("sessionContext")).get("sessionIssuer"))
        arn = field(data, "arn")
        resource = arn.split(":", 5)[-1]
        arn_parts = resource.split("/")
        if len(arn_parts) >= 3 and arn_parts[0] == "assumed-role":
            session = arn_parts[-1]
        else:
            session = field(data, "principalId").partition(":")[2]
        name = field(issuer, "userName") or (
            arn_parts[-2] if len(arn_parts) >= 3 else ""
        )
        if name.startswith("AWSReservedSSO_") and session:
            return Identity(actor_account, "sso_user", f"sso:{session}"), session
        return (Identity(actor_account, "role", name) if name else None), session
    if kind == "Root":
        return Identity(actor_account, "root", "root"), ""
    if kind == "IAMUser" and name:
        return Identity(actor_account, "user", name), ""
    if kind in {"FederatedUser", "SAMLUser", "WebIdentityUser"}:
        name = name or field(data, "principalId")
        return (Identity(actor_account, "federated", name) if name else None), ""
    return None, ""


def normalize(record: dict[str, Any]) -> Event:
    event_id = field(record, "eventID")
    event_name = field(record, "eventName")
    event_source = field(record, "eventSource")
    category = field(record, "eventCategory") or "Management"
    account = field(record, "recipientAccountId") or field(
        obj(record.get("userIdentity")), "accountId"
    )
    if (
        not event_id
        or not event_name
        or not event_source
        or not ACCOUNT.fullmatch(account)
        or not isinstance(record.get("userIdentity"), dict)
    ):
        raise InvalidCloudTrail(
            "Missing CloudTrail event identity, account, or operation"
        )
    try:
        time = datetime.fromisoformat(field(record, "eventTime"))
        if time.tzinfo is None:
            raise ValueError
        time = time.astimezone(UTC)
    except (ValueError, OverflowError) as error:
        raise InvalidCloudTrail("Invalid CloudTrail event timestamp") from error
    request = obj(record.get("requestParameters"))
    principal = obj(record.get("userIdentity"))
    mfa = bool_value(obj(record.get("additionalEventData")).get("MFAUsed"))
    if mfa is None:
        mfa = bool_value(
            obj(obj(principal.get("sessionContext")).get("attributes")).get(
                "mfaAuthenticated"
            )
        )
    identity, session = attribute(record, account)
    resources = record.get("resources")
    resource = obj(resources[0]) if isinstance(resources, list) and resources else {}
    return Event(
        event_id=event_id,
        time=time,
        account_id=account,
        name=event_name,
        source=event_source,
        category=category,
        region=field(record, "awsRegion"),
        source_ip=field(record, "sourceIPAddress"),
        identity=identity,
        read_only=bool_value(record.get("readOnly")),
        user_agent=field(record, "userAgent"),
        error_code=field(record, "errorCode"),
        access_key_id=field(principal, "accessKeyId"),
        session_name=session or field(request, "roleSessionName"),
        target=field(request, "roleArn")
        or field(request, "userName")
        or field(resource, "ARN"),
        mfa_used=mfa,
        vpc_endpoint_id=field(record, "vpcEndpointId"),
        with_decryption=bool_value(request.get("withDecryption")) is True,
        raw=record,
    )


def read_cloudtrail(body: bytes) -> list[Event]:
    if len(body) > MAX_UPLOAD:
        raise InvalidCloudTrail("CloudTrail upload exceeds 20 MiB")
    try:
        if body.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                body = stream.read(MAX_UNPACKED + 1)
        if len(body) > MAX_UNPACKED:
            raise InvalidCloudTrail("Decompressed CloudTrail upload exceeds 100 MiB")
        document = json.loads(body)
    except (
        OSError,
        EOFError,
        zlib.error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as error:
        raise InvalidCloudTrail("Could not decode CloudTrail JSON or gzip") from error
    records = obj(document).get("Records")
    if not isinstance(records, list) or any(
        not isinstance(record, dict) for record in records
    ):
        raise InvalidCloudTrail(
            'CloudTrail document must contain a "Records" array of objects'
        )
    return [normalize(record) for record in records]
