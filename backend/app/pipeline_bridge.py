"""Relay normalized event outbox entries to Kafka and commit after ClickHouse insertion."""

import os
from datetime import UTC, datetime
from pathlib import Path
from time import sleep
from typing import Any

import clickhouse_connect
from clickhouse_connect.driver.client import Client
from confluent_kafka import (
    Consumer,
    KafkaError,
    KafkaException,
    Message,
    Producer,
    TopicPartition,
)

from app.repository import Repository, identity_id
from app.wire.events_pb2 import NormalizedEvent

TOPIC = "ig.events.normalized.v1"
BATCH = 300


def clickhouse() -> Client:
    return clickhouse_connect.get_client(
        host=os.environ["IG_CLICKHOUSE_HOST"],
        username=os.getenv("IG_CLICKHOUSE_USER", "identityguard"),
        password=os.getenv("IG_CLICKHOUSE_PASSWORD", ""),
        database="identityguard",
        connect_timeout=3,
        send_receive_timeout=8,
    )


def publish(repo: Repository, producer: Producer) -> int:
    pending = repo.pending_events(BATCH)
    if not pending:
        return 0
    failures: list[KafkaError] = []

    def delivered(error: KafkaError | None, _message: Message) -> None:
        if error is not None:
            failures.append(error)

    for event in pending:
        actor = identity_id(event.identity) if event.identity else ""
        record = NormalizedEvent(
            event_id=event.event_id,
            account_id=event.account_id,
            identity_id=actor,
            occurred_ms=int(event.time.timestamp() * 1000),
            event_name=event.name,
            event_source=event.source,
            event_category=event.category,
            aws_region=event.region,
        )
        producer.produce(
            TOPIC,
            key=actor or event.account_id,
            value=record.SerializeToString(),
            on_delivery=delivered,
        )
    if producer.flush(10) or failures:
        raise RuntimeError("Kafka could not confirm the outbox batch")
    repo.mark_published([event.event_id for event in pending])
    return len(pending)


def sink(database: Client, consumer: Consumer) -> int:
    messages = consumer.consume(num_messages=BATCH, timeout=0.2)
    offsets: dict[int, int] = {}
    batch: list[list[Any]] = []
    for message in messages:
        if error := message.error():
            if error.retriable() or error.code() == KafkaError.UNKNOWN_TOPIC_OR_PART:
                continue
            raise KafkaException(error)
        payload, partition, offset = (
            message.value(),
            message.partition(),
            message.offset(),
        )
        if payload is None or partition is None or offset is None:
            raise ValueError("Kafka record is missing its body or position")
        record = NormalizedEvent.FromString(payload)
        batch.append(
            [
                record.event_id,
                record.account_id,
                record.identity_id,
                datetime.fromtimestamp(record.occurred_ms / 1000, UTC),
                record.event_name,
                record.event_source,
                record.event_category,
                record.aws_region,
            ]
        )
        offsets[partition] = offset + 1
    if batch:
        database.insert(
            "events",
            batch,
            column_names=[
                "event_id",
                "account_id",
                "identity_id",
                "event_time",
                "event_name",
                "event_source",
                "event_category",
                "aws_region",
            ],
        )
        consumer.commit(
            offsets=[
                TopicPartition(TOPIC, partition, offset)
                for partition, offset in offsets.items()
            ],
            asynchronous=False,
        )
    return len(batch)


def main() -> None:
    repo = Repository(Path(os.environ["IG_DATABASE"]))
    repo.backfill_outbox()
    address = os.environ["IG_KAFKA_ADDRESS"]
    producer = Producer(
        {
            "bootstrap.servers": address,
            "enable.idempotence": True,
            "message.timeout.ms": 8000,
        }
    )
    consumer = Consumer(
        {
            "bootstrap.servers": address,
            "group.id": "ig-clickhouse-v1",
            "enable.auto.commit": False,
            "auto.offset.reset": "earliest",
            "allow.auto.create.topics": True,
        }
    )
    database = clickhouse()
    consumer.subscribe([TOPIC])
    try:
        while True:
            sent = publish(repo, producer)
            inserted = sink(database, consumer)
            if not sent and not inserted:
                sleep(0.25)
    finally:
        consumer.close()
        database.close()


if __name__ == "__main__":
    main()
