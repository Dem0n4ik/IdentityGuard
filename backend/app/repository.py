"""Transactional store for the single-user local development environment."""

import json
import os
import re
import sqlite3
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal, TypedDict

from app.engine.access import CloudSnapshot, Graph
from app.engine.adjustments import Adjustments, ExceptionRecord
from app.engine.detections import Rule, parse_rule
from app.engine.events import (
    Event,
    Identity,
    Network,
    aws_public_networks,
    outside_networks,
    source_prefix,
)
from app.engine.model import CLOUD, Model
from app.engine.posture import Snapshot
from app.engine.scoring import (
    BENIGN,
    Window,
    WindowKey,
    active_risk,
    exposure,
    quadrant,
    role_edges,
)
from app.pipeline import CLOSURE_GRACE, closed_boundary, evaluate_events, state_at

Source = Literal["demo", "aws"]
Status = Literal["new", "investigating", "responded", "closed"]
SIMULATION_SETTING = "simulation_v1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, time TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_time ON events(time);
CREATE TABLE IF NOT EXISTS event_outbox (
    event_id TEXT PRIMARY KEY REFERENCES events(id), published_at TEXT
);
CREATE INDEX IF NOT EXISTS outbox_status ON event_outbox(published_at);
CREATE TRIGGER IF NOT EXISTS events_to_outbox AFTER INSERT ON events
BEGIN INSERT OR IGNORE INTO event_outbox(event_id) VALUES (NEW.id); END;
CREATE TABLE IF NOT EXISTS windows (
    id TEXT PRIMARY KEY, hour TEXT NOT NULL, risk REAL NOT NULL,
    level TEXT NOT NULL, data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY REFERENCES windows(id), status TEXT NOT NULL DEFAULT 'new',
    verdict TEXT, reason TEXT, note TEXT NOT NULL DEFAULT '', detected_at TEXT NOT NULL,
    resolved_at TEXT, auto_resolution TEXT, case_id TEXT, version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS incident_response (
    id TEXT PRIMARY KEY REFERENCES incidents(id), first_response_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_case ON incidents(case_id);
CREATE TABLE IF NOT EXISTS response_actions (
    id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id),
    target TEXT NOT NULL, at TEXT NOT NULL, api TEXT NOT NULL, params TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posture (
    id TEXT NOT NULL, taken_at TEXT NOT NULL, identity TEXT NOT NULL, snapshot TEXT NOT NULL,
    PRIMARY KEY (id, taken_at)
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY, at TEXT NOT NULL, action TEXT NOT NULL,
    target TEXT NOT NULL, details TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_action_at ON audit(action, at);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
"""


class ImportResult(TypedDict):
    inserted: int
    events: int
    attributed: int
    identities: int
    windows: int
    incidents: int
    high: int


def encode(value: Any) -> str:
    def convert(item: Any) -> str | list[Any]:
        if isinstance(item, datetime):
            return item.isoformat()
        if isinstance(item, frozenset):
            return sorted(item)
        raise TypeError(f"Cannot serialize {type(item).__name__}")

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=convert,
    )


def identity_id(identity: Identity) -> str:
    return f"{identity.account_id}:{identity.kind}:{identity.name}"


def window_id(window: Window) -> str:
    return f"{identity_id(window.identity)}:{window.hour:%Y%m%d%H}"


def read_event(data: str) -> Event:
    payload = json.loads(data)
    payload["time"] = datetime.fromisoformat(payload["time"])
    if payload["identity"] is not None:
        payload["identity"] = Identity(**payload["identity"])
    return Event(**payload)


def update_hash(previous: str, value: str) -> str:
    from hashlib import sha256

    return sha256(bytes.fromhex(previous) + value.encode("utf-8")).hexdigest()


def audit(
    connection: sqlite3.Connection,
    time: datetime,
    action: str,
    target: str,
    details: dict[str, Any],
) -> None:
    prior = connection.execute(
        "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    seq, previous = (prior["seq"] + 1, prior["hash"]) if prior else (1, "00" * 32)
    at = time.isoformat()
    value = encode(
        {"seq": seq, "at": at, "action": action, "target": target, "details": details}
    )
    connection.execute(
        "INSERT INTO audit VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            seq,
            at,
            action,
            target,
            encode(details),
            previous,
            update_hash(previous, value),
        ),
    )


class Conflict(ValueError):
    pass


class Repository:
    def __init__(
        self,
        path: Path,
        source: Source = "demo",
        snapshots: dict[Identity, tuple[Snapshot, ...]] | None = None,
        trusted: tuple[Network, ...] = (),
    ) -> None:
        self.path = path
        self.source = source
        self.snapshots = snapshots or {}
        self.trusted = trusted
        ranges = os.environ.get("IG_AWS_IP_RANGES") if source == "aws" else None
        self.scoring_networks = trusted
        self.coverage_breaks = tuple(
            datetime.fromisoformat(value.strip())
            for value in os.environ.get("IG_CLOUDTRAIL_COVERAGE_BREAKS", "").split(",")
            if value.strip()
        )
        if any(value.utcoffset() is None for value in self.coverage_breaks):
            raise ValueError("CloudTrail coverage boundaries must include a UTC offset")
        if ranges:
            document = json.loads(Path(ranges).read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("Invalid AWS IP range document")
            self.scoring_networks += aws_public_networks(document)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(SCHEMA)
            connection.execute(
                "INSERT OR IGNORE INTO metadata VALUES ('source', ?)", (source,)
            )
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'source'"
            ).fetchone()
            if row["value"] != source:
                raise ValueError("This database belongs to a different data source")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def account_in(connection: sqlite3.Connection) -> str | None:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key='aws_account'"
        ).fetchone()
        if row:
            return str(row["value"])
        rows = connection.execute("""
            SELECT json_extract(data, '$.account_id') AS account FROM events
            UNION SELECT json_extract(identity, '$.account_id') AS account FROM posture
            LIMIT 2
        """).fetchall()
        if len(rows) > 1:
            raise Conflict("The database already contains multiple AWS accounts")
        return str(rows[0]["account"]) if rows else None

    def bound_account(self) -> str | None:
        with self.connect() as connection:
            return self.account_in(connection)

    @classmethod
    def ensure_account(cls, connection: sqlite3.Connection, accounts: set[str]) -> None:
        if not accounts:
            return
        account = cls.account_in(connection)
        if len(accounts) > 1 or account is not None and account not in accounts:
            raise Conflict(
                "Use a separate private workspace database for each AWS account"
            )
        connection.execute(
            "INSERT OR IGNORE INTO metadata VALUES ('aws_account', ?)",
            (next(iter(accounts)),),
        )

    def pin_account(self, account: str) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.ensure_account(connection, {account})

    def read_setting(self, key: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            return self.setting_in(connection, key)

    @staticmethod
    def setting_in(connection: sqlite3.Connection, key: str) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key=?", (key,)
        ).fetchone()
        if row is None:
            return None
        value = json.loads(row["value"])
        if not isinstance(value, dict):
            raise TypeError("Invalid workspace setting")
        return value

    @staticmethod
    def write_setting(
        connection: sqlite3.Connection, key: str, value: dict[str, Any]
    ) -> None:
        connection.execute(
            """
            INSERT INTO metadata VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """,
            (key, encode(value)),
        )

    def change_setting(
        self,
        key: str,
        apply: Callable[[dict[str, Any]], dict[str, Any]],
        action: str,
        *,
        rescore: bool = False,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = apply(self.setting_in(connection, key) or {})
            self.write_setting(connection, key, result)
            if rescore:
                self.refresh_windows(connection, now)
                result = self.setting_in(connection, key) or result
            audit(connection, now, action, self.source, {})
            return result

    def save_setting(
        self,
        key: str,
        value: dict[str, Any],
        action: str,
        *,
        target: str | None = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO metadata VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
                (key, encode(value)),
            )
            audit(connection, datetime.now(UTC), action, target or self.source, {})

    def record_action(self, action: str, target: str, details: dict[str, Any]) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            audit(connection, datetime.now(UTC), action, target, details)

    def reserve_assistant(self, case_id: str, language: str) -> bool:
        now = datetime.now(UTC)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute(
                """
                SELECT count(*) FROM audit WHERE action='assistant.requested' AND at >= ?
            """,
                ((now - timedelta(hours=1)).isoformat(),),
            ).fetchone()[0]
            if count >= 30:
                return False
            audit(
                connection, now, "assistant.requested", case_id, {"language": language}
            )
            return True

    def ingest(
        self,
        events: Iterable[Event],
        now: datetime,
        *,
        seed_start: datetime | None = None,
    ) -> ImportResult:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'seed_start'"
            ).fetchone()
            if seed_start is not None:
                if self.source != "demo":
                    raise ValueError("Only a demo database can be seeded")
                if row and row["value"] != seed_start.isoformat():
                    raise ValueError(
                        "Choose a new database to seed another 21-day period"
                    )
                connection.execute(
                    "INSERT OR IGNORE INTO metadata VALUES ('seed_start', ?)",
                    (seed_start.isoformat(),),
                )
                self.insert_posture(connection, self.snapshots)
            if self.source == "aws":
                events = list(events)
                self.ensure_account(connection, {event.account_id for event in events})
            inserted = connection.executemany(
                "INSERT OR IGNORE INTO events VALUES (?, ?, ?)",
                (
                    (event.event_id, event.time.isoformat(), encode(asdict(event)))
                    for event in events
                ),
            ).rowcount
            all_events, windows = self.refresh_windows(connection, now)
            stats = connection.execute("""
                SELECT count(*) AS incidents, count(*) FILTER (WHERE level = 'high') AS high
                FROM windows WHERE level IN ('medium', 'high')
            """).fetchone()
            result = ImportResult(
                inserted=inserted,
                events=len(all_events),
                windows=len(windows),
                attributed=sum(event.identity is not None for event in all_events),
                identities=len(
                    {
                        event.identity
                        for event in all_events
                        if event.identity is not None
                    }
                ),
                incidents=stats["incidents"],
                high=stats["high"],
            )
            audit(connection, now, "events.ingested", self.source, dict(result))
            return result

    def score_data(
        self,
        connection: sqlite3.Connection,
        now: datetime,
        *,
        model: Model | None = None,
        proposed_rule: Rule | None = None,
        rule_config: list[dict[str, Any]] | None = None,
    ) -> tuple[list[Event], dict[WindowKey, Window], Adjustments]:
        all_events = [
            read_event(row["data"])
            for row in connection.execute("SELECT data FROM events")
        ]
        feedback = {}
        for row in connection.execute("""
            SELECT w.data, i.verdict FROM incidents i JOIN windows w ON w.id=i.id
            WHERE i.status='closed' AND i.verdict IS NOT NULL
        """):
            payload = json.loads(row["data"])
            key = (
                Identity(**payload["identity"]),
                datetime.fromisoformat(payload["hour"]),
            )
            feedback[key] = row["verdict"]
        revisions = (
            rule_config
            if rule_config is not None
            else self.active_rule_config(connection)
        )
        rules = [parse_rule(row["yaml"]) for row in revisions]
        if proposed_rule:
            rules = [
                rule
                for rule in rules
                if rule.definition.id != proposed_rule.definition.id
            ] + [proposed_rule]
        exceptions = [
            ExceptionRecord.model_validate(item)
            for item in (self.setting_in(connection, "suppressions") or {}).get(
                "items", []
            )
        ]
        adjust = Adjustments(rules, exceptions, now)
        if model is None:
            model = CLOUD
            if revisions:
                revision_hash = sha256(encode(revisions).encode()).hexdigest()[:12]
                model = replace(CLOUD, version=f"{CLOUD.version}+{revision_hash}")
        row = connection.execute(
            "SELECT value FROM metadata WHERE key='seed_start'"
        ).fetchone()
        start = (
            datetime.fromisoformat(row["value"]) + timedelta(days=14) if row else None
        )
        simulation = (
            self.setting_in(connection, SIMULATION_SETTING)
            if self.source == "demo"
            else None
        ) or {}
        starts = {
            Identity(**item["identity"]): datetime.fromisoformat(item["at"])
            for item in simulation.get("monitoring_starts", [])
        }
        windows = evaluate_events(
            all_events,
            self.load_posture(connection),
            now,
            model,
            start=start,
            monitoring_starts=starts,
            trusted=self.scoring_networks,
            coverage_breaks=self.coverage_breaks,
            feedback=feedback,
            adjust=adjust if rules or adjust.exceptions else None,
            capture_evidence=True,
        )
        return all_events, windows, adjust

    def active_rule_config(
        self, connection: sqlite3.Connection
    ) -> list[dict[str, Any]]:
        latest = {}
        for item in (self.setting_in(connection, "detections") or {}).get("items", []):
            if item["status"] != "draft":
                latest[item["id"]] = item
        return [row for _, row in sorted(latest.items()) if row["status"] == "enabled"]

    def refresh_windows(
        self,
        connection: sqlite3.Connection,
        now: datetime,
    ) -> tuple[list[Event], dict[WindowKey, Window]]:
        previous = self.last_boundary(connection)
        if previous is not None:
            now = max(now, previous + CLOSURE_GRACE)
        events, windows, adjustments = self.score_data(connection, now)
        established = {
            str(row["id"]) for row in connection.execute("SELECT id FROM incidents")
        }
        ids = self.update_windows(connection, windows.values(), now)
        self.correlate(connection, events, ids, established)
        exceptions = self.setting_in(connection, "suppressions")
        if exceptions:
            for item in exceptions["items"]:
                item["hits"] = len(adjustments.hits[item["id"]])
            self.write_setting(connection, "suppressions", exceptions)
        self.write_setting(
            connection,
            "scoring_progress",
            {"boundary": closed_boundary(now).isoformat()},
        )
        return events, windows

    def backfill_outbox(self) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO event_outbox(event_id) SELECT id FROM events"
            )

    def pending_events(self, limit: int) -> list[Event]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT e.data FROM event_outbox o JOIN events e ON e.id=o.event_id
                WHERE o.published_at IS NULL ORDER BY o.rowid LIMIT ?
            """,
                (limit,),
            ).fetchall()
        return [read_event(row["data"]) for row in rows]

    def mark_published(self, event_ids: list[str]) -> None:
        timestamp = datetime.now(UTC).isoformat()
        with self.connect() as connection:
            connection.executemany(
                "UPDATE event_outbox SET published_at=? WHERE event_id=? AND published_at IS NULL",
                ((timestamp, key) for key in event_ids),
            )

    def outbox_counts(self) -> tuple[int, int]:
        with self.connect() as connection:
            row = connection.execute("""
                SELECT count(*) FILTER (WHERE published_at IS NULL), count(published_at) FROM event_outbox
            """).fetchone()
            return int(row[0]), int(row[1])

    def last_boundary(self, connection: sqlite3.Connection) -> datetime | None:
        progress = self.setting_in(connection, "scoring_progress")
        return datetime.fromisoformat(progress["boundary"]) if progress else None

    def scoring_boundary(self) -> datetime | None:
        with self.connect() as connection:
            return self.last_boundary(connection)

    def pending_boundary(self, now: datetime) -> datetime | None:
        with self.connect() as connection:
            return self.pending_in(connection, now)

    def pending_in(
        self, connection: sqlite3.Connection, now: datetime
    ) -> datetime | None:
        candidate = closed_boundary(now)
        last = self.last_boundary(connection)
        if last is not None and candidate <= last:
            return None
        start = last.isoformat() if last else ""
        row = connection.execute(
            """
            SELECT 1 FROM events WHERE time >= ? AND time < ?
            AND json_extract(data, '$.identity') IS NOT NULL LIMIT 1
        """,
            (start, candidate.isoformat()),
        ).fetchone()
        return candidate if row else None

    def close_due(self, now: datetime, *, task_id: str | None = None) -> bool:
        if self.pending_boundary(now) is None:
            return False
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if self.pending_in(connection, now) is None:
                return False
            self.refresh_windows(connection, now)
            audit(
                connection,
                now,
                "risk.auto_scored",
                self.source,
                {"workflow_id": task_id},
            )
            return True

    def rescore(self, *, task_id: str | None = None) -> None:
        now = datetime.now(UTC)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if task_id and self.setting_in(connection, f"workflow:{task_id}"):
                return
            self.refresh_windows(connection, now)
            if task_id:
                self.write_setting(
                    connection, f"workflow:{task_id}", {"completed": True}
                )
            audit(
                connection, now, "risk.rescored", self.source, {"workflow_id": task_id}
            )

    def update_windows(
        self,
        connection: sqlite3.Connection,
        windows: Iterable[Window],
        now: datetime,
    ) -> dict[tuple[Identity, datetime], str]:
        incident_ids: dict[tuple[Identity, datetime], str] = {}
        for window in windows:
            key = window_id(window)
            serialized = encode(asdict(window))
            updated = connection.execute(
                """
                INSERT INTO windows VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET risk=excluded.risk, level=excluded.level, data=excluded.data
                WHERE windows.data != excluded.data
            """,
                (key, window.hour.isoformat(), window.risk, window.level, serialized),
            )
            if updated.rowcount:
                connection.execute(
                    "UPDATE incidents SET version=version+1 WHERE id=?", (key,)
                )
            if window.level == "low":
                connection.execute(
                    """
                    UPDATE incidents SET status='closed', resolved_at=?, auto_resolution='rescored_low',
                    version=version+1 WHERE id=? AND status!='closed'
                """,
                    (now.isoformat(), key),
                )
            else:
                incident_ids[window.identity, window.hour] = key
                connection.execute(
                    """
                    INSERT OR IGNORE INTO incidents (id, detected_at, case_id) VALUES (?, ?, ?)
                """,
                    (key, (window.hour + timedelta(hours=1)).isoformat(), key),
                )
        return incident_ids

    def correlate(
        self,
        connection: sqlite3.Connection,
        events: list[Event],
        ids: dict[tuple[Identity, datetime], str],
        established: set[str],
    ) -> None:
        parents = {key: key for key in ids.values()}
        six_hours = timedelta(hours=6)

        def root(key: str) -> str:
            while parents[key] != key:
                parents[key] = parents[parents[key]]
                key = parents[key]
            return key

        def join(left: str, right: str) -> None:
            a, b = sorted((root(left), root(right)))
            parents[b] = a

        linked: dict[tuple[str, str], tuple[datetime, str]] = {}
        for event in sorted(events, key=lambda item: (item.time, item.event_id)):
            if event.identity is None or (event.identity, event.hour) not in ids:
                continue
            current = ids[event.identity, event.hour]
            pivots = {
                "key": event.access_key_id,
                "session": event.session_name,
                "network": source_prefix(event.source_ip)
                if outside_networks(event.source_ip, self.trusted)
                else "",
            }
            for kind, value in pivots.items():
                if not value:
                    continue
                previous = linked.get((kind, value))
                if previous and event.hour - previous[0] <= six_hours:
                    join(previous[1], current)
                linked[kind, value] = event.hour, current

        by_identity: dict[Identity, list[tuple[datetime, str]]] = defaultdict(list)
        for (identity, hour), key in ids.items():
            by_identity[identity].append((hour, key))
        for edge in role_edges(events):
            for left_hour, left in by_identity[edge.source]:
                if abs(left_hour - edge.time) <= six_hours:
                    for right_hour, right in by_identity[edge.target]:
                        if (
                            abs(left_hour - right_hour) <= six_hours
                            and abs(right_hour - edge.time) <= six_hours
                        ):
                            join(left, right)

        rows = connection.execute(
            "SELECT id, case_id, detected_at FROM incidents ORDER BY detected_at, id"
        ).fetchall()
        cases: dict[str, str] = {}
        for row in sorted(rows, key=lambda record: record["id"] not in established):
            if row["id"] in parents:
                cases.setdefault(root(row["id"]), row["case_id"] or row["id"])
        connection.executemany(
            "UPDATE incidents SET case_id=? WHERE id=? AND case_id!=?",
            (
                (cases[root(key)], key, cases[root(key)])
                for key in parents
                if key not in established
            ),
        )

    def incidents(
        self,
        since: datetime | None = None,
        *,
        case_id: str | None = None,
        accounts: Iterable[str] = (),
    ) -> list[dict[str, Any]]:
        scope = json.dumps(list(accounts))
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT i.*, w.data, r.first_response_at FROM incidents i JOIN windows w ON w.id = i.id LEFT JOIN incident_response r ON r.id=i.id
                WHERE (? IS NULL OR w.hour >= ?) AND (? IS NULL OR i.case_id = ?)
                AND (?='[]' OR json_extract(w.data,'$.identity.account_id') IN (SELECT value FROM json_each(?)))
                ORDER BY w.hour DESC, w.risk DESC, i.id
            """,
                (since.isoformat() if since else None,) * 2
                + (case_id, case_id, scope, scope),
            ).fetchall()
        return [self.present_incident(row) for row in rows]

    def present_incident(self, row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        window = json.loads(result.pop("data"))
        window.pop("event_scores")
        window.pop("evidence", None)
        return {**window, **result}

    def patch_incident(
        self,
        key: str,
        version: int,
        status: Status,
        verdict: str | None,
        reason: str | None,
        note: str,
        now: datetime,
        *,
        accounts: Iterable[str] = (),
    ) -> dict[str, Any]:
        scope = json.dumps(list(accounts))
        if status == "closed" and (
            not reason or verdict not in BENIGN | {"true_positive"}
        ):
            raise ValueError("A verdict and reason are required to close an incident")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT version,status,note,verdict,resolved_at FROM incidents i JOIN windows w ON w.id=i.id
                   WHERE i.id=? AND (?='[]' OR json_extract(w.data,'$.identity.account_id') IN (SELECT value FROM json_each(?)))""",
                (key, scope, scope),
            ).fetchone()
            if not row:
                raise KeyError(key)
            if row["version"] != version:
                raise Conflict("The incident has changed. Reload it before saving.")
            connection.execute(
                """
                UPDATE incidents SET status=?, verdict=?, reason=?, note=?, resolved_at=?,
                auto_resolution=NULL, version=version+1 WHERE id=?
            """,
                (
                    status,
                    verdict,
                    reason,
                    note,
                    (row["resolved_at"] or now.isoformat())
                    if status == "closed"
                    else None,
                    key,
                ),
            )
            if status != "new" or note.strip() and note != row["note"]:
                self.capture_response(connection, key, now)
            audit(
                connection,
                now,
                "incident.updated",
                key,
                {"status": status, "verdict": verdict},
            )
            result = connection.execute(
                """
                SELECT i.*, w.data, r.first_response_at FROM incidents i JOIN windows w ON w.id = i.id LEFT JOIN incident_response r ON r.id=i.id WHERE i.id=?
            """,
                (key,),
            ).fetchone()
            return self.present_incident(result)

    @staticmethod
    def capture_response(
        connection: sqlite3.Connection, key: str, now: datetime
    ) -> None:
        connection.execute(
            "INSERT OR IGNORE INTO incident_response VALUES (?, ?)",
            (key, now.isoformat()),
        )

    def isolate_user_dry_run(
        self,
        incident_id: str,
        confirmation: str,
        request_id: str,
        now: datetime,
    ) -> dict[str, Any]:
        if self.source != "demo":
            raise ValueError("The AWS workspace is read-only")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT * FROM response_actions WHERE id=?", (request_id,)
            ).fetchone()
            if prior:
                if (
                    prior["incident_id"] != incident_id
                    or prior["target"] != confirmation
                ):
                    raise Conflict("This idempotency key belongs to another request")
                return dict(prior) | {
                    "params": json.loads(prior["params"]),
                    "mode": "dry_run",
                }
            row = connection.execute(
                """
                SELECT w.data, i.status FROM incidents i JOIN windows w ON w.id=i.id WHERE i.id=?
            """,
                (incident_id,),
            ).fetchone()
            if not row:
                raise KeyError(incident_id)
            identity = Identity(**json.loads(row["data"])["identity"])
            if row["status"] == "closed":
                raise Conflict("A closed incident cannot request isolation")
            if identity.kind != "user" or not re.fullmatch(
                r"[A-Za-z0-9_+=,.@-]{1,64}", identity.name
            ):
                raise ValueError("This action requires an IAM user")
            if confirmation != identity.name:
                raise ValueError("The confirmation must exactly match the IAM username")
            params = {
                "UserName": identity.name,
                "PolicyArn": "arn:aws:iam::aws:policy/AWSDenyAll",
            }
            result = {
                "id": request_id,
                "incident_id": incident_id,
                "target": identity.name,
                "at": now.isoformat(),
                "api": "iam:AttachUserPolicy",
                "params": params,
                "mode": "dry_run",
            }
            connection.execute(
                "INSERT INTO response_actions VALUES (?, ?, ?, ?, ?, ?)",
                (
                    request_id,
                    incident_id,
                    identity.name,
                    result["at"],
                    result["api"],
                    encode(params),
                ),
            )
            connection.execute(
                "UPDATE incidents SET status='responded', version=version+1 WHERE id=?",
                (incident_id,),
            )
            self.capture_response(connection, incident_id, now)
            audit(
                connection,
                now,
                "response.isolation.dry_run",
                incident_id,
                {"request_id": request_id, "api": result["api"]},
            )
            return result

    def newest_event_time(self, account: str) -> datetime | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT max(time) FROM events WHERE json_extract(data, '$.account_id')=?
            """,
                (account,),
            ).fetchone()
        return datetime.fromisoformat(row[0]) if row and row[0] else None

    def role_chain_inputs(
        self, since: datetime
    ) -> tuple[list[Event], dict[WindowKey, float]]:
        from app.engine.scoring import ASSUME

        with self.connect() as connection:
            names = sorted(ASSUME)
            event_rows = connection.execute(
                """
                SELECT data FROM events WHERE time>=? AND json_extract(data, '$.name') IN (?, ?, ?)
                ORDER BY time DESC LIMIT 100000
            """,
                (since.isoformat(), *names),
            ).fetchall()
            windows = connection.execute(
                "SELECT data FROM windows WHERE hour>=?",
                ((since - timedelta(hours=4)).isoformat(),),
            ).fetchall()
        scores = {}
        for row in windows:
            data = json.loads(row["data"])
            scores[
                Identity(**data["identity"]), datetime.fromisoformat(data["hour"])
            ] = float(data["risk"])
        return [read_event(row["data"]) for row in event_rows], scores

    def save_cloud_snapshot(self, cloud: CloudSnapshot) -> None:
        graph = Graph(cloud.nodes, cloud.edges)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.ensure_account(connection, {cloud.account_id})
            previous = self.load_posture(connection)
            changes: dict[Identity, tuple[Snapshot, ...]] = {}
            for node in cloud.nodes:
                if node.kind not in {"role", "user"}:
                    continue
                identity = Identity(node.account_id, node.kind, node.name)
                baseline = state_at(
                    previous.get(identity, ()), cloud.taken_at
                ) or Snapshot(cloud.taken_at)
                reachable = any(
                    graph.nodes[key].critical
                    for key in graph.search(node.id)[0]
                    if key != node.id
                )
                changes[identity] = (
                    replace(baseline, critical=reachable, taken_at=cloud.taken_at),
                )
            self.insert_posture(connection, changes)
            self.write_setting(
                connection, "cloud_snapshot", cloud.model_dump(mode="json")
            )
            audit(
                connection,
                cloud.taken_at,
                "cloud.synced",
                self.source,
                {"nodes": len(cloud.nodes), "edges": len(cloud.edges)},
            )

    def event_page(
        self,
        *,
        identity: str = "",
        operation: str = "",
        account: str = "",
        allowed_accounts: tuple[str, ...] = (),
        region: str = "",
        category: str = "",
        limit: int = 100,
        before: tuple[str, str] | None = None,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        scope = json.dumps(allowed_accounts)
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT data FROM events
                WHERE (? = '' OR json_extract(data, '$.account_id') = ?)
                AND (?='[]' OR (json_extract(data, '$.account_id') IN (SELECT value FROM json_each(?))
                     AND COALESCE(json_extract(data, '$.identity.account_id'),json_extract(data, '$.account_id'))
                         IN (SELECT value FROM json_each(?))))
                AND (? = '' OR instr(lower(json_extract(data, '$.name')), lower(?)) > 0)
                AND (? = '' OR json_extract(data, '$.identity.account_id') || ':' ||
                     json_extract(data, '$.identity.kind') || ':' || json_extract(data, '$.identity.name') = ?)
                AND (? = '' OR json_extract(data, '$.region') = ?)
                AND (? = '' OR json_extract(data, '$.category') = ?)
                AND (? IS NULL OR time >= ?)
                AND (? IS NULL OR (time,id) < (?,?))
                ORDER BY time DESC, id DESC LIMIT ?
            """,
                (
                    account,
                    account,
                    scope,
                    scope,
                    scope,
                    operation,
                    operation,
                    identity,
                    identity,
                    region,
                    region,
                    category,
                    category,
                    since.isoformat() if since else None,
                    since.isoformat() if since else None,
                    before[0] if before else None,
                    *(before or (None, None)),
                    limit,
                ),
            ).fetchall()
        return [self.public_event(row["data"]) for row in rows]

    @staticmethod
    def public_event(payload: str) -> dict[str, Any]:
        event: dict[str, Any] = json.loads(payload)
        event.pop("raw")
        if event["access_key_id"]:
            event["access_key_id"] = "…" + event["access_key_id"][-4:]
        return event

    def events_by_id(
        self, identifiers: list[str], *, accounts: Iterable[str] = ()
    ) -> list[dict[str, Any]]:
        if not identifiers:
            return []
        scope = json.dumps(list(accounts))
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT e.data FROM json_each(?) ordered JOIN events e ON e.id=ordered.value
                WHERE (?='[]' OR (json_extract(e.data, '$.account_id') IN (SELECT value FROM json_each(?))
                    AND COALESCE(json_extract(e.data, '$.identity.account_id'),json_extract(e.data, '$.account_id'))
                        IN (SELECT value FROM json_each(?))))
                ORDER BY ordered.key
            """,
                (json.dumps(identifiers), scope, scope, scope),
            ).fetchall()
        return [self.public_event(row["data"]) for row in rows]

    def identities(
        self, now: datetime, *, accounts: Iterable[str] = ()
    ) -> list[dict[str, Any]]:
        allowed = frozenset(accounts)
        scope = json.dumps(sorted(allowed))
        with self.connect() as connection:
            snapshots = self.load_posture(connection)
            actors = connection.execute(
                """
                SELECT DISTINCT json_extract(data, '$.identity') AS identity FROM events
                WHERE json_extract(data, '$.identity.name') IS NOT NULL
                AND (?='[]' OR json_extract(data, '$.identity.account_id') IN (SELECT value FROM json_each(?)))
            """,
                (scope, scope),
            ).fetchall()
            rows = connection.execute(
                """SELECT data FROM windows WHERE hour >= ?
                   AND (?='[]' OR json_extract(data,'$.identity.account_id') IN (SELECT value FROM json_each(?)))""",
                ((now - timedelta(days=7)).isoformat(), scope, scope),
            ).fetchall()
        windows: dict[Identity, list[Window]] = defaultdict(list)
        for row in rows:
            data = json.loads(row["data"])
            data["hour"] = datetime.fromisoformat(data["hour"])
            data["identity"] = Identity(**data["identity"])
            windows[data["identity"]].append(Window(**data))
        identities = {
            identity
            for identity in snapshots
            if not allowed or identity.account_id in allowed
        }
        identities.update(Identity(**json.loads(row["identity"])) for row in actors)
        result = []
        for identity in sorted(identities):
            snapshot = state_at(snapshots.get(identity, ()), now)
            facts = set(snapshot.facts(identity) if snapshot else ())
            recent = windows[identity]
            if not recent or "thin_baseline" in max(recent, key=lambda w: w.hour).facts:
                facts.add("thin_baseline")
            risk, state = active_risk(recent, now), exposure(facts)
            result.append(
                {
                    **asdict(identity),
                    "id": identity_id(identity),
                    "risk": risk,
                    "exposure": state,
                    "quadrant": quadrant(risk, state),
                    "facts": sorted(facts),
                }
            )
        return sorted(result, key=lambda row: (-row["risk"], row["id"]))

    def save_posture(
        self,
        inventory: dict[Identity, tuple[Snapshot, ...]],
        now: datetime,
    ) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if self.source == "aws":
                self.ensure_account(
                    connection, {identity.account_id for identity in inventory}
                )
            self.insert_posture(connection, inventory)
            audit(
                connection,
                now,
                "posture.synced",
                self.source,
                {"identities": len(inventory)},
            )

    @staticmethod
    def insert_posture(
        connection: sqlite3.Connection, inventory: dict[Identity, tuple[Snapshot, ...]]
    ) -> None:
        connection.executemany(
            "INSERT OR IGNORE INTO posture VALUES (?, ?, ?, ?)",
            (
                (
                    identity_id(identity),
                    snapshot.taken_at.isoformat(),
                    encode(asdict(identity)),
                    encode(asdict(snapshot)),
                )
                for identity, snapshots in inventory.items()
                for snapshot in snapshots
            ),
        )

    def load_posture(
        self, connection: sqlite3.Connection
    ) -> dict[Identity, tuple[Snapshot, ...]]:
        snapshots: dict[Identity, list[Snapshot]] = defaultdict(list)
        for identity, history in self.snapshots.items():
            snapshots[identity].extend(history)
        for row in connection.execute(
            "SELECT identity, snapshot FROM posture ORDER BY taken_at"
        ):
            data = json.loads(row["snapshot"])
            data["taken_at"] = datetime.fromisoformat(data["taken_at"])
            data["actions"] = frozenset(data["actions"])
            snapshots[Identity(**json.loads(row["identity"]))].append(Snapshot(**data))
        return {identity: tuple(history) for identity, history in snapshots.items()}

    def audit_entries(self, limit: int = 100) -> tuple[bool, list[dict[str, Any]]]:
        with self.connect() as connection:
            records = [
                dict(row)
                for row in connection.execute("SELECT * FROM audit ORDER BY seq")
            ]
        previous = "00" * 32
        valid = True
        for seq, row in enumerate(records, 1):
            value = {key: row[key] for key in ("seq", "at", "action", "target")}
            value["details"] = json.loads(row["details"])
            if (
                row["seq"] != seq
                or row["prev_hash"] != previous
                or row["hash"] != update_hash(previous, encode(value))
            ):
                valid = False
            previous = row["hash"]
            row["details"] = value["details"]
        return valid, records[-limit:][::-1]
