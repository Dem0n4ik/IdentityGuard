"""Local pipeline status for the optional service stack."""

import os
from datetime import datetime

from clickhouse_connect.driver.exceptions import ClickHouseError
from fastapi import APIRouter
from pydantic import BaseModel

from app.analytics import enabled, reader
from app.repository import Repository


class PipelineStatus(BaseModel):
    kafka_configured: bool
    temporal_configured: bool
    outbox_pending: int
    outbox_published: int
    clickhouse_events: int | None
    scoring_through: datetime | None


def router_for(repository: Repository) -> APIRouter:
    router = APIRouter()

    @router.get("/pipeline", operation_id="getPipelineStatus")
    def status() -> PipelineStatus:
        pending, published = repository.outbox_counts()
        stored = None
        if enabled(repository):
            try:
                client = reader()
                try:
                    row = client.query(
                        "SELECT uniqExact(event_id) FROM events"
                    ).first_row
                    stored = int(row[0]) if row else 0
                finally:
                    client.close()
            except (OSError, ClickHouseError, KeyError):
                pass
        return PipelineStatus(
            kafka_configured=bool(os.getenv("IG_KAFKA_ADDRESS")),
            temporal_configured=bool(os.getenv("IG_TEMPORAL_ADDRESS")),
            outbox_pending=pending,
            outbox_published=published,
            clickhouse_events=stored,
            scoring_through=repository.scoring_boundary(),
        )

    return router
