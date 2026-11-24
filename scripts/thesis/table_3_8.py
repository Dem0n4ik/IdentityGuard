"""Таблиця 3.8: порівняння підходів на перевірному наборі Д2.

Запуск із кореня репозиторію:
    PYTHONPATH=backend uv run --locked python scripts/thesis/table_3_8.py
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path

from app.devdata import CORP, generate, static_windows
from app.engine.model import CLOUD, CORE
from app.pipeline import evaluate_events

sys.path.insert(0, str(Path(__file__).parent))
from common import END_DAY, SEED, clopper_pearson, pr_auc, prf, roc_auc, window_labels

ROWS = {
    "static": "Статичні правила",
    "equal_m1": "Рівні ваги без контексту",
    "ahp_m1": "Ваги AHP без контексту",
    "equal_ctx": "Рівні ваги з контекстом",
    "core": "Базовий профіль",
    "full": "Розширений профіль",
}


def run(end_day: date) -> dict[str, object]:
    data = generate(end_day)
    now = data.end + timedelta(minutes=15)
    labels = window_labels(data.events, data.labels)
    equal = {key: 1 / len(CLOUD.weights) for key in CLOUD.weights}
    variants = {
        "equal_m1": replace(CLOUD, weights=equal, facts={}),
        "ahp_m1": replace(CLOUD, facts={}),
        "equal_ctx": replace(CLOUD, weights=equal),
        "core": CORE,
        "full": CLOUD,
    }
    scored = {
        name: evaluate_events(
            data.events, data.snapshots, now, model, start=data.score_from, trusted=CORP
        )
        for name, model in variants.items()
    }
    keys = list(scored["full"])
    attack = {k: any(x.startswith("S") for x in labels[k]) for k in keys}
    att = [attack[k] for k in keys]
    static = static_windows(data.events)
    st = [k in static for k in keys]
    table: dict[str, dict[str, object]] = {
        "static": {
            **prf(list(zip(st, att))),
            "f1_r50": prf(list(zip(st, att)))["f1"],
            "f1_high": prf(list(zip(st, att)))["f1"],
            "roc_auc": roc_auc(
                [float(s) for s, a in zip(st, att) if a],
                [float(s) for s, a in zip(st, att) if not a],
            ),
            "pr_auc": pr_auc([float(s) for s in st], att),
        }
    }
    for name, windows in scored.items():
        risk = [windows[k].risk for k in keys]
        table[name] = {
            **prf([(windows[k].level != "low", attack[k]) for k in keys]),
            "f1_r50": prf([(windows[k].risk >= 50, attack[k]) for k in keys])["f1"],
            "f1_high": prf([(windows[k].level == "high", attack[k]) for k in keys])[
                "f1"
            ],
            "roc_auc": roc_auc(
                [r for r, a in zip(risk, att) if a],
                [r for r, a in zip(risk, att) if not a],
            ),
            "pr_auc": pr_auc(risk, att),
        }
    full = table["full"]
    negatives = len(keys) - sum(att)
    return {
        "end_day": end_day.isoformat(),
        "seed": SEED,
        "events": len(data.events),
        "windows": len(keys),
        "positive": sum(att),
        "negative": negatives,
        "table": table,
        "ci95_recall": clopper_pearson(int(full["tp"]), sum(att)),
        "ci95_fpr": clopper_pearson(int(full["fp"]), negatives),
    }


def markdown(result: dict[str, object]) -> str:
    head = "| Підхід | TP | FP | FN | Влучність | Повнота | F1 | F1, R ≥ 50 | F1, високий рівень | ROC-AUC | PR-AUC |"
    lines = [head, "|" + " --- |" * 11]
    table = result["table"]
    assert isinstance(table, dict)
    for key, title in ROWS.items():
        r = table[key]
        lines.append(
            f"| {title} | {r['tp']} | {r['fp']} | {r['fn']} | {r['precision']:.3f} | {r['recall']:.3f} | "
            f"{r['f1']:.3f} | {r['f1_r50']:.3f} | {r['f1_high']:.3f} | {r['roc_auc']:.3f} | {r['pr_auc']:.3f} |"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--end-day", type=date.fromisoformat, default=END_DAY)
    parser.add_argument("--out", type=Path, default=Path("reports/thesis"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    result = run(args.end_day)
    (args.out / "table_3_8.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    print(
        f"Подій: {result['events']}, вікон: {result['windows']}, з атаками: {result['positive']}"
    )
    print(markdown(result))
    print(
        "95 % інтервал повноти:",
        result["ci95_recall"],
        "частки хибних спрацювань:",
        result["ci95_fpr"],
    )
