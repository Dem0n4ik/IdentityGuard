"""Replay pinned public Stratus CloudTrail samples against the risk engine."""

import argparse
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta
from hashlib import sha256
from io import BytesIO
from pathlib import Path, PurePosixPath
from urllib.request import urlopen
from uuid import NAMESPACE_URL, uuid5
from zipfile import ZipFile

from app.devdata import (
    ABLATION_METHOD,
    ACTORS,
    CORP,
    generate,
    score_with_ablation,
    static_windows,
    window_metrics,
)
from app.engine.detections import Rule, parse_rule
from app.engine.events import Event
from app.engine.scoring import Window, WindowKey
from app.ingest import normalize

COMMIT = "df3316f6f73a219eba715a505f2b4742a9cce197"
CORPUS_SHA256 = "23a37d29c01cab62f1fd52787d3a97cacdc89f9df7aaa93e8296f12d3aa93260"
TECHNIQUES = 36
END_DAY = date(2026, 11, 7)
DEFAULT_LOGS = Path("devdata/stratus")
DEFAULT_REPORT = Path("reports/stratus.md")
ARCHIVE_URL = f"https://codeload.github.com/DataDog/stratus-red-team/zip/{COMMIT}"
SOURCE_URL = (
    f"https://github.com/DataDog/stratus-red-team/tree/{COMMIT}/docs/detonation-logs"
)


def validate_logs(files: Mapping[str, bytes]) -> None:
    digest = sha256()
    for name, body in sorted(files.items()):
        digest.update(name.encode() + b"\0" + sha256(body).digest())
    if len(files) != TECHNIQUES or digest.hexdigest() != CORPUS_SHA256:
        raise ValueError("CloudTrail files do not match the pinned Stratus corpus")


def fetch(destination: Path) -> None:
    limit = 24 * 1024 * 1024
    with urlopen(ARCHIVE_URL, timeout=30) as response:
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError("Stratus archive exceeded the size limit")
    with ZipFile(BytesIO(body)) as archive:
        paths = [
            info
            for info in archive.infolist()
            if (
                (path := PurePosixPath(info.filename)).match(
                    "*/docs/detonation-logs/aws.*.json"
                )
                and len(path.parts) == 4
            )
        ]
        if len(paths) != TECHNIQUES or sum(info.file_size for info in paths) > limit:
            raise ValueError("Unexpected Stratus archive contents")
        files = {
            PurePosixPath(info.filename).name: archive.read(info) for info in paths
        }
    validate_logs(files)
    destination.mkdir(parents=True, exist_ok=True)
    for name, contents in files.items():
        (destination / name).write_bytes(contents)


def read_logs(directory: Path) -> dict[str, list[Event]]:
    files = {
        path.name: path.read_bytes().replace(b"\r\n", b"\n")
        for path in directory.glob("aws.*.json")
    }
    validate_logs(files)
    return {
        Path(name).stem: sorted(
            (normalize(record) for record in json.loads(body)),
            key=lambda event: (event.time, event.event_id),
        )
        for name, body in sorted(files.items())
    }


@dataclass(frozen=True, slots=True)
class ReplayedTechnique:
    name: str
    key: WindowKey
    events: tuple[Event, ...]


def place_logs(
    logs: Mapping[str, list[Event]], score_from: datetime
) -> list[ReplayedTechnique]:
    actors = tuple(actor for actor in ACTORS if actor.kind == "user" and actor.ops)
    workdays = tuple(
        day
        for offset in range(7)
        if (day := score_from + timedelta(days=offset)).weekday() < 5
    )
    placed = []
    for index, (technique, source) in enumerate(sorted(logs.items())):
        if not source:
            raise ValueError(f"No CloudTrail records for {technique}")
        round_number, actor_index = divmod(index, len(actors))
        actor = actors[actor_index]
        hour = actor.start + round_number % (actor.end - actor.start + 1)
        start = workdays[round_number] + timedelta(hours=hour)
        duration = source[-1].time - source[0].time
        max_duration = timedelta(minutes=55)
        scale = min(1.0, max_duration / duration) if duration else 1.0
        events = tuple(
            replace(
                event,
                event_id=str(
                    uuid5(
                        NAMESPACE_URL,
                        f"{COMMIT}/{technique}/{position}/{event.event_id}",
                    )
                ),
                identity=actor.identity,
                account_id=actor.account,
                time=start + (event.time - source[0].time) * scale,
            )
            for position, event in enumerate(source)
        )
        placed.append(ReplayedTechnique(technique, (actor.identity, start), events))
    return placed


def report_replay(
    logs: Mapping[str, list[Event]],
    end_day: date = END_DAY,
    rules: tuple[Rule, ...] = (),
) -> tuple[str, bool]:
    dataset = generate(end_day, include_attacks=False)
    attacks = place_logs(logs, dataset.score_from)
    evaluation_time = dataset.end + timedelta(minutes=15)
    windows, ablated = score_with_ablation(
        [*dataset.events, *(event for attack in attacks for event in attack.events)],
        dataset.snapshots,
        evaluation_time,
        dataset.score_from,
        trusted=CORP,
        rules=rules,
    )
    scored: dict[str, Window] = {attack.name: windows[attack.key] for attack in attacks}
    attack_keys = {attack.key for attack in attacks}
    metrics = window_metrics(windows, ablated, attack_keys)
    false_static = len((static_windows(dataset.events) & windows.keys()) - attack_keys)
    false_high = sum(
        window.level == "high" and key not in attack_keys
        for key, window in windows.items()
    )
    false_medium = sum(
        window.level == "medium" and key not in attack_keys
        for key, window in windows.items()
    )
    detected = sum(window.risk >= 25 for window in scored.values())
    above_30 = sum(window.risk >= 30 for window in scored.values())
    checks = (
        (
            detected == TECHNIQUES,
            f"R ≥ 25 for all techniques ({detected}/{TECHNIQUES})",
        ),
        (
            above_30 >= 30,
            f"R ≥ 30 for at least 30 techniques ({above_30}/{TECHNIQUES})",
        ),
        (false_high == 0, f"Zero high severity background windows ({false_high})"),
    )
    report = [
        "# Stratus Red Team CloudTrail replay",
        "",
        f"Source: [DataDog/stratus-red-team at `{COMMIT}`]({SOURCE_URL}).",
        f"Corpus SHA-256: `{CORPUS_SHA256}`.",
        f"Evaluation ends {dataset.end:%Y-%m-%d %H:%M} UTC. Model: `cloud-v2`.",
        "",
        "Public CloudTrail events were replayed over the IdentityGuard synthetic background.",
        "Techniques are ordered by identifier and assigned round-robin to baseline IAM users with a normal schedule.",
        "Replay substitutes the scoring identity, account, time, and event ID. Operation, region, source address, and result are preserved.",
        "Relative intervals are preserved unless the capture exceeds 55 minutes, in which case they are scaled proportionally.",
        "S1–S9 are excluded. Evaluation labels are kept outside the risk engine.",
        "Detection rules: "
        + (
            ", ".join(rule.definition.id for rule in rules)
            if rules
            else "base model only"
        )
        + ".",
        "",
        f"Evaluated windows: {len(windows)}. Background false positives: {false_medium} medium, {false_high} high.",
        "",
        ABLATION_METHOD,
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        *(f"| {label} | {value:.6f} |" for label, value in metrics.items()),
        f"| Static false positives | {false_static} |",
        "",
        "## Acceptance",
        "",
        *(f"- [{'x' if passed else ' '}] {label}" for passed, label in checks),
        "",
        "## Results",
        "",
        "| Technique | Replay identity | Events | B | M | R | Level |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- |",
        *(
            f"| `{attack.name}` | {attack.key[0].name} | {len(attack.events)} | "
            f"{window.behavior:.4f} | {window.modifier:.2f} | {window.risk:.2f} | {window.level} |"
            for attack in attacks
            for window in (scored[attack.name],)
        ),
    ]
    return "\n".join(report) + "\n", all(passed for passed, _ in checks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fetch", "replay"))
    parser.add_argument("--logs", type=Path, default=DEFAULT_LOGS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--end-day", type=date.fromisoformat, default=END_DAY)
    parser.add_argument("--rules", action="append", type=Path, default=[])
    args = parser.parse_args()
    if args.command == "fetch":
        fetch(args.logs)
        print(f"Verified {TECHNIQUES} Stratus CloudTrail files in {args.logs}.")
        return 0
    rules = tuple(parse_rule(path.read_text(encoding="utf-8")) for path in args.rules)
    report, passed = report_replay(read_logs(args.logs), args.end_day, rules)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report, encoding="utf-8", newline="\n")
    print(
        f"Stratus acceptance {'passed' if passed else 'failed'}. Report: {args.report}."
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
