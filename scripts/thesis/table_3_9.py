"""Таблиця 3.9: відтворення 36 технік Stratus Red Team (набір Д3) на фоні Д2.

Чотири прогони: модель / модель з правилом, оригінальні регіон і адреси /
легітимні регіон і мережа ідентичності.
Попередньо: make fetch-stratus (коміт df3316f, перевірка SHA-256 корпусу).

    PYTHONPATH=backend uv run --locked python scripts/thesis/table_3_9.py
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path

from app.devdata import BY_NAME, CORP, generate, score_with_ablation, static_windows
from app.engine.detections import parse_rule
from app.stratus import DEFAULT_LOGS, place_logs, read_logs

sys.path.insert(0, str(Path(__file__).parent))
from common import END_DAY, clopper_pearson

RULE = Path("config/detections/aws-sensitive-control-plane.yml")
TACTICS = {
    "initial-access": "Початковий доступ",
    "execution": "Виконання",
    "persistence": "Закріплення",
    "privilege-escalation": "Підвищення привілеїв",
    "defense-evasion": "Уникнення виявлення",
    "credential-access": "Доступ до облікових даних",
    "discovery": "Розвідка",
    "lateral-movement": "Бокове переміщення",
    "exfiltration": "Ексфільтрація",
    "impact": "Вплив",
}


def run(end_day: date, logs: Path, legit: bool, with_rule: bool) -> dict[str, object]:
    rules = (parse_rule(RULE.read_text(encoding="utf-8")),) if with_rule else ()
    data = generate(end_day, include_attacks=False)
    attacks = place_logs(read_logs(logs), data.score_from)
    if legit:
        attacks = [
            replace(
                a,
                events=tuple(
                    replace(
                        e,
                        region=BY_NAME[a.key[0].name].regions[0],
                        source_ip=f"203.0.113.{10 + i % 150}",
                    )
                    for i, e in enumerate(a.events)
                ),
            )
            for a in attacks
        ]
    windows, _ = score_with_ablation(
        [*data.events, *(e for a in attacks for e in a.events)],
        data.snapshots,
        data.end + timedelta(minutes=15),
        data.score_from,
        trusted=CORP,
        rules=rules,
    )
    keys = {a.key for a in attacks}
    det = {a.name: windows[a.key] for a in attacks}
    detected = sum(w.level != "low" for w in det.values())
    negatives = len(windows) - len(keys)
    by_tactic: dict[str, list[int]] = {t: [0, 0, 0] for t in TACTICS}
    for name, w in det.items():
        tactic = name.split(".")[1]
        by_tactic[tactic][0] += 1
        by_tactic[tactic][1] += w.level != "low"
        by_tactic[tactic][2] += w.level == "high"
    return {
        "detected": detected,
        "high": sum(w.level == "high" for w in det.values()),
        "ci95_detected": clopper_pearson(detected, len(det)),
        "fp": sum(w.level != "low" for k, w in windows.items() if k not in keys),
        "negatives": negatives,
        "static_fp": len((static_windows(data.events) & windows.keys()) - keys),
        "by_tactic": by_tactic,
        "fired": dict(
            Counter(i for w in det.values() for i, v in w.indicators.items() if v > 0)
        ),
        "missed": sorted(n for n, w in det.items() if w.level == "low"),
        "risk": {n: round(w.risk, 2) for n, w in det.items()},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--end-day", type=date.fromisoformat, default=END_DAY)
    parser.add_argument("--logs", type=Path, default=DEFAULT_LOGS)
    parser.add_argument("--out", type=Path, default=Path("reports/thesis"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    runs = {
        f"{'legit' if legit else 'original'}{'+rule' if rule else ''}": run(
            args.end_day, args.logs, legit, rule
        )
        for legit in (False, True)
        for rule in (False, True)
    }
    (args.out / "table_3_9.json").write_text(
        json.dumps(runs, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    print(
        "| Тактика | Технік | Модель | З правилом | Легітимні регіон і мережа: модель / з правилом |"
    )
    print("| --- | ---: | ---: | ---: | ---: |")
    for tactic, title in TACTICS.items():
        o, r, lg, lr = (
            runs[k]["by_tactic"][tactic]
            for k in ("original", "original+rule", "legit", "legit+rule")
        )
        print(f"| {title} | {o[0]} | {o[1]} | {r[1]} | {lg[1]} / {lr[1]} |")
    for name, r in runs.items():
        print(
            f"{name}: виявлено {r['detected']}/36, високий {r['high']}, хибні {r['fp']}/{r['negatives']}, "
            f"статичні правила {r['static_fp']}"
        )
