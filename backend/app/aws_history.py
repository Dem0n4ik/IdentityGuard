"""Scoped, read-only CloudTrail management-event import."""

import argparse
import json
import re
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import sleep

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.engine.events import Event
from app.ingest import ACCOUNT, InvalidCloudTrail, normalize
from app.repository import Repository


class AccountMismatch(ValueError):
    pass


def verified_session(
    account_id: str, region: str, profile: str | None = None
) -> tuple[boto3.Session, Config]:
    if not ACCOUNT.fullmatch(account_id) or not re.fullmatch(
        r"[a-z]{2}(?:-[a-z]+)+-\d", region
    ):
        raise ValueError("Expected a 12-digit account and an explicit AWS region")
    config = Config(
        retries={"mode": "adaptive", "max_attempts": 3},
        connect_timeout=5,
        read_timeout=20,
        ignore_configured_endpoint_urls=True,  # type: ignore[call-arg]
    )
    session = boto3.Session(profile_name=profile, region_name=region)
    sts = session.client("sts", config=config)
    caller = sts.get_caller_identity()
    if caller["Account"] != account_id:
        raise AccountMismatch("AWS account did not match the requested account")
    if caller["Arn"].endswith(":root"):
        raise AccountMismatch("Import requires a non-root IAM principal")
    return session, config


def lookup(
    account_id: str,
    region: str,
    days: int,
    max_pages: int,
    profile: str | None = None,
) -> Iterator[Event]:
    if not 1 <= days <= 90 or not 1 <= max_pages <= 2000:
        raise ValueError("Invalid lookback or pagination limit")
    session, config = verified_session(account_id, region, profile)
    trail = session.client("cloudtrail", config=config)
    end = datetime.now(UTC)
    pages = trail.get_paginator("lookup_events").paginate(
        StartTime=end - timedelta(days=days),
        EndTime=end,
        PaginationConfig={"PageSize": 50},
    )
    for number, page in enumerate(pages, 1):
        for row in page.get("Events", []):
            event = normalize(json.loads(row["CloudTrailEvent"]))
            if event.account_id == account_id:
                yield event
        if not page.get("NextToken"):
            return
        if number == max_pages:
            raise ValueError(
                "CloudTrail history exceeded the page limit. Increase the limit or reduce the lookback."
            )
        sleep(0.52)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--days", type=int, default=21)
    parser.add_argument("--max-pages", type=int, default=200)
    parser.add_argument("--profile")
    args = parser.parse_args()
    try:
        events = list(
            lookup(args.account, args.region, args.days, args.max_pages, args.profile)
        )
        repository = Repository(args.database, source="aws")
        result = repository.ingest(events, datetime.now(UTC))
    except ClientError as error:
        operation = error.operation_name
        error_code = error.response.get("Error", {}).get("Code", "Unknown")
        print(f"AWS {operation} returned {error_code}.", file=sys.stderr)
        return 1
    except BotoCoreError as error:
        print(f"AWS connection failed ({type(error).__name__}).", file=sys.stderr)
        return 1
    except (AccountMismatch, InvalidCloudTrail, ValueError) as error:
        print(f"Import stopped ({type(error).__name__}).", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
