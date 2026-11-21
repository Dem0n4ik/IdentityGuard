"""Evaluate the unchanged risk model on an independently collected CloudTrail test split."""

import argparse
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.request import urlopen
from zipfile import ZipFile

from app.devdata import (
    ABLATION_METHOD,
    score_with_ablation,
    static_windows,
    window_metrics,
)
from app.engine.detections import parse_rule
from app.engine.events import Event
from app.engine.scoring import WindowKey
from app.ingest import normalize
from app.pipeline import CLOSURE_GRACE, evaluate_events

COMMIT = "18d3f248f4def592f4e86152c3fcb54506fbcbf6"
SOURCE = f"https://github.com/ArielCyber/cloud_log_sampling/tree/{COMMIT}"
ARCHIVE = (
    f"https://raw.githubusercontent.com/ArielCyber/cloud_log_sampling/{COMMIT}"
    "/TestOn/labeled_cloudtrail_a.zip"
)
SHA256 = "d5dce3dbdb61ffb935e16cb4728aaca933daa42201a672dfad7387fd168f6eb0"
RECORDS_FILE = "merged_cloudtrail.json"
START = datetime(2026, 4, 4, tzinfo=UTC)
END = START + timedelta(days=1)
DEFAULT_CACHE = Path("data/independent/labeled_cloudtrail_a.zip")
DEFAULT_RULE = Path("config/detections/aws-sensitive-control-plane.yml")


def load_records(cache: Path) -> list[dict[str, Any]]:
    limit = 8 * 1024 * 1024
    if cache.exists():
        with cache.open("rb") as stream:
            payload = stream.read(limit + 1)
    else:
        with urlopen(ARCHIVE, timeout=25) as stream:
            payload = stream.read(limit + 1)
    if len(payload) > limit or sha256(payload).hexdigest() != SHA256:
        raise ValueError("Archive does not match the pinned Ariel Cyber test split")
    with ZipFile(BytesIO(payload)) as archive:
        if archive.getinfo(RECORDS_FILE).file_size > 100 * 1024 * 1024:
            raise ValueError("Uncompressed benchmark exceeds the size limit")
        document = json.loads(archive.read(RECORDS_FILE))
    records = document["Records"]
    if not isinstance(records, list) or not records:
        raise ValueError("Ariel Cyber archive is missing CloudTrail records")
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not cache.exists():
        cache.write_bytes(payload)
    return records


def evaluate(records: list[dict[str, Any]], rule_path: Path) -> str:
    events: dict[str, Event] = {}
    labels: dict[str, str] = {}
    for raw in records:
        attack = raw["attack_name"] if raw["should_sample"] else ""
        # Use the production normalizer with the corpus labels removed.
        event = normalize(
            {
                key: value
                for key, value in raw.items()
                if key not in {"attack_name", "should_sample"}
            }
        )
        if event.event_id in events:
            if labels[event.event_id] != attack or events[event.event_id] != event:
                raise ValueError("Conflicting records for the same CloudTrail event ID")
            continue
        events[event.event_id] = event
        labels[event.event_id] = attack

    attack_records: Counter[str] = Counter()
    unattributed: Counter[str] = Counter()
    attacks: dict[str, set[WindowKey]] = defaultdict(set)
    for event in events.values():
        name = labels[event.event_id]
        if not name or not START <= event.time < END:
            continue
        attack_records[name] += 1
        if event.identity is None:
            unattributed[name] += 1
        else:
            attacks[name].add((event.identity, event.hour))

    attack_keys = set().union(*attacks.values())
    rule_yaml = rule_path.read_text(encoding="utf-8")
    rule = parse_rule(rule_yaml)
    rule_digest = sha256(rule_yaml.encode("utf-8")).hexdigest()
    now = END + CLOSURE_GRACE
    # The test file contains separate historical and concurrent captures.
    without_boundaries = evaluate_events(events.values(), {}, now, start=START)
    coverage_breaks = (START,)
    base, base_ablated = score_with_ablation(
        events.values(), {}, now, START, coverage_breaks=coverage_breaks
    )
    extended, extended_ablated = score_with_ablation(
        events.values(), {}, now, START, rules=(rule,), coverage_breaks=coverage_breaks
    )
    if (
        base.keys() != extended.keys()
        or not attack_keys
        or not attack_keys <= base.keys()
    ):
        raise ValueError("Benchmark labels and scored windows do not align")
    base_metrics = window_metrics(base, base_ablated, attack_keys)
    extended_metrics = window_metrics(extended, extended_ablated, attack_keys)
    static_false = len((static_windows(events.values()) & base.keys()) - attack_keys)
    tested_records = sum(START <= event.time < END for event in events.values())
    false_before = sum(
        window.level != "low" and key not in attack_keys
        for key, window in without_boundaries.items()
    )
    false_after = sum(
        window.level != "low" and key not in attack_keys for key, window in base.items()
    )
    detected_before = sum(without_boundaries[key].level != "low" for key in attack_keys)
    detected_after = sum(base[key].level != "low" for key in attack_keys)

    report = [
        "# Independent CloudTrail evaluation",
        "",
        f"Source: [Ariel Cyber Innovation Center test split]({SOURCE}), commit `{COMMIT}`.",
        f"Archive SHA-256: `{SHA256}`.",
        f"Evaluation period: {START:%Y-%m-%d} UTC, the corpus's concurrent attack and benign capture.",
        "",
        (
            "The original identities and times are preserved. The earlier records are outside the 14-day lookback "
            "for April 4, and the corpus provides no IAM posture snapshots. This run therefore measures cold-start performance. "
            "April 4 is declared a collection boundary, so the gap between captures cannot supply dormancy evidence. "
            "An identity-hour is positive if it contains an attributed attack record. "
            "Multiple scenarios can share one window. A detected window counts for each scenario it contains."
        ),
        "",
        (
            f"Unique records: **{len(events)}** from {len(records)} source rows. "
            f"Records in the evaluation period: **{tested_records}**. Scored windows: **{len(base)}**. "
            f"Positive windows: **{len(attack_keys)}**. Unattributed attack records: **{sum(unattributed.values())}**."
        ),
        "",
        (
            f"The extended run applies the existing `{rule.definition.id}` rule, developed on Stratus. "
            f"Rule SHA-256: `{rule_digest}`."
        ),
        "",
        (
            f"Declaring the boundary changes base-model false positives from **{false_before} to {false_after}** "
            f"and detected positive windows from **{detected_before}/{len(attack_keys)} to {detected_after}/{len(attack_keys)}**."
        ),
        "",
        ABLATION_METHOD,
        "",
        "| Metric | Base cloud-v2 | With AWS rule |",
        "| --- | ---: | ---: |",
        *(
            f"| {name} | {value:.6f} | {extended_metrics[name]:.6f} |"
            for name, value in base_metrics.items()
        ),
        *(
            f"| False {severity} | {sum(window.level == severity and key not in attack_keys for key, window in base.items())} "
            f"| {sum(window.level == severity and key not in attack_keys for key, window in extended.items())} |"
            for severity in ("medium", "high")
        ),
        f"| Static baseline false positives | {static_false} | {static_false} |",
        "",
        "| Scenario | Unique attack records | Unattributed | Positive windows | Detected base | Detected with rule |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
        *(
            f"| `{name}` | {count} | {unattributed[name]} | {len(attacks[name])} "
            f"| {sum(base[key].level != 'low' for key in attacks[name])} "
            f"| {sum(extended[key].level != 'low' for key in attacks[name])} |"
            for name, count in sorted(attack_records.items())
        ),
    ]
    return "\n".join(report) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--rule", type=Path, default=DEFAULT_RULE)
    parser.add_argument("--report", type=Path, default=Path("reports/independent.md"))
    args = parser.parse_args()
    report = evaluate(load_records(args.cache), args.rule)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report, encoding="utf-8", newline="\n")
    print(f"Independent evaluation written to {args.report}.")


if __name__ == "__main__":
    main()
