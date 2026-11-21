"""Read-only ClickHouse search and ordered projection of indexed events."""

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import clickhouse_connect
from clickhouse_connect.driver.client import Client

from app.repository import Repository

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class Search:
    identity: str = ""
    operation: str = ""
    account: str = ""
    allowed_accounts: tuple[str, ...] = ()
    region: str = ""
    category: str = ""
    before: tuple[str, str] | None = None
    since: datetime | None = None
    limit: int = 100


def enabled(repository: Repository) -> bool:
    return repository.source == "demo" and os.getenv("IG_CLICKHOUSE_HUNT") == "1"


def reader() -> Client:
    return clickhouse_connect.get_client(
        host=os.environ["IG_CLICKHOUSE_HOST"],
        username=os.getenv("IG_CLICKHOUSE_READER_USER", "ig_hunt_reader"),
        password=os.environ["IG_CLICKHOUSE_READER_PASSWORD"],
        database="identityguard",
        connect_timeout=3,
        send_receive_timeout=8,
        autogenerate_session_id=False,
    )


def milliseconds(value: datetime) -> int:
    delta = value - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000


def build_query(search: Search) -> tuple[str, dict[str, str | int]]:
    clauses = []
    values: dict[str, str | int] = {"page_size": search.limit}
    for name, clause, value in (
        ("account", "account_id = {account:String}", search.account),
        ("identity", "identity_id = {identity:String}", search.identity),
        (
            "operation",
            "positionCaseInsensitive(event_name, {operation:String}) > 0",
            search.operation,
        ),
        ("region", "aws_region = {region:String}", search.region),
        ("category", "event_category = {category:String}", search.category),
    ):
        if value:
            clauses.append(clause)
            values[name] = value
    if search.allowed_accounts:
        values["allowed_accounts"] = ",".join(search.allowed_accounts)
        clauses.append("account_id IN splitByChar(',', {allowed_accounts:String})")
    if search.since:
        clauses.append(
            "event_time >= fromUnixTimestamp64Milli({since_ms:Int64}, 'UTC')"
        )
        values["since_ms"] = milliseconds(search.since)
    if search.before:
        time, identifier = search.before
        clauses.append(
            "(event_time, event_id) < (fromUnixTimestamp64Milli({before_ms:Int64}, 'UTC'), {before_id:String})"
        )
        values["before_ms"] = milliseconds(datetime.fromisoformat(time))
        values["before_id"] = identifier
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    query = (
        "SELECT event_id FROM identityguard.events FINAL"
        + where
        + " ORDER BY event_time DESC, event_id DESC LIMIT {page_size:UInt16}"
        + " SETTINGS max_execution_time = 5, max_rows_to_read = 10000000, read_overflow_mode = 'throw'"
    )
    return query, values


def search_index(repository: Repository, search: Search) -> list[dict[str, Any]]:
    query, parameters = build_query(search)
    client = reader()
    try:
        identifiers = [
            str(row[0])
            for row in client.query(query, parameters=parameters).result_rows
        ]
    finally:
        client.close()
    if search.allowed_accounts:
        return repository.events_by_id(identifiers, accounts=search.allowed_accounts)
    return repository.events_by_id(identifiers)
