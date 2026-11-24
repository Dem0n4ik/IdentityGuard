"""Аналіз чутливості моделі IdentityGuard до параметрів (зауваження керівника).

Запуск із кореня репозиторію:
    PYTHONPATH=backend uv run --locked python scripts/thesis/sensitivity.py

Рушій не змінюється: параметри підміняються на час окремого прогону
(тривалість вікна, тривалість базового періоду, поріг підтримки s,
поріг недостатньої бази, коефіцієнти фактів стану c_k).
"""

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import app.engine.events as ev
import app.engine.scoring as sc
import app.pipeline as pp
import polars as pl
from app.devdata import CORP, generate
from app.engine.model import CLOUD

sys.path.insert(0, str(Path(__file__).parent))
from common import END_DAY, clopper_pearson

ORIG = {
    "hour_start": ev.hour_start,
    "event_frame": sc.event_frame,
    "build_profile": sc.build_profile,
}


def set_params(window_min=60, days=14, s=2, thin=50):
    def floor(value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Event time must have a timezone")
        v = value.astimezone(UTC).replace(second=0, microsecond=0)
        return v.replace(minute=(v.minute // window_min) * window_min)

    def frame(events):
        f = ORIG["event_frame"](events)
        return f.with_columns(
            pl.col("time").dt.truncate(f"{window_min}m").alias("window")
        )

    def profile(events, day, excluded_hours=frozenset()):
        day = day.replace(hour=0, minute=0, second=0, microsecond=0)
        fr = frame(events).filter(
            (pl.col("time") >= day - timedelta(days=days))
            & (pl.col("time") < day)
            & ~pl.col("window").is_in(sorted(excluded_hours))
        )
        if fr.is_empty():
            return None
        hourly = fr.group_by("window").len()
        mean, std = hourly.select(
            pl.col("len").mean().alias("m"), pl.col("len").std(ddof=0).alias("s")
        ).row(0)
        sets = [
            frozenset(fr.group_by(c).len().filter(pl.col("len") >= s)[c])
            for c in ("region", "prefix", "operation", "hour")
        ]
        n = fr.height
        return sc.Profile(
            *sets,
            float(mean),
            max(1.0, float(std or 0)),
            round(n * 50 / thin),
            fr.select(pl.col("time").dt.date().n_unique()).item(),
        )

    ev.hour_start = floor
    pp.hour_start = floor
    sc.event_frame = frame
    pp.build_profile = profile
    sc.build_profile = profile


def prf(pairs):
    tp = sum(d and a for d, a in pairs)
    fp = sum(d and not a for d, a in pairs)
    fn = sum(a and not d for d, a in pairs)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "f1": 2 * tp / (2 * tp + fp + fn) if tp else 0.0,
    }


def run(model=CLOUD, **params):
    set_params(**params)
    data = generate(END_DAY)
    now = data.end + timedelta(minutes=15)
    windows = pp.evaluate_events(
        data.events, data.snapshots, now, model, start=data.score_from, trusted=CORP
    )
    labels = defaultdict(set)
    first = {}
    for e in data.events:
        if e.identity is not None and e.event_id in data.labels:
            lab = data.labels[e.event_id]
            labels[e.identity, e.hour].add(lab)
            if lab.startswith("S"):
                first[lab] = min(first.get(lab, e.time), e.time)
    keys = list(windows)
    attack = {k: any(x.startswith("S") for x in labels[k]) for k in keys}
    inc = prf([(windows[k].level != "low", attack[k]) for k in keys])
    high = prf([(windows[k].level == "high", attack[k]) for k in keys])
    # виявлення сценаріїв і затримка (від першої події атаки до кінця першого вікна з інцидентом)
    wlen = timedelta(minutes=params.get("window_min", 60))
    scen = {}
    for lab in sorted(first):
        hits = sorted(
            k[1] for k in keys if lab in labels[k] and windows[k].level != "low"
        )
        scen[lab] = (hits[0] + wlen - first[lab]).total_seconds() / 60 if hits else None
    lat = [v for v in scen.values() if v is not None]
    rare = [
        w for k, w in windows.items() if k[0].name == "marko-support" and not attack[k]
    ]
    benign_max = max(
        (windows[k].risk for k in keys if not attack[k] and labels[k]), default=0
    )
    return {
        "params": params,
        "windows": len(keys),
        "positive": sum(attack.values()),
        "incident": inc,
        "high": high,
        "scenarios_detected": sum(v is not None for v in scen.values()),
        "scenarios": len(scen),
        "latency_mean_min": sum(lat) / len(lat) if lat else None,
        "latency_max_min": max(lat) if lat else None,
        "rare_fp": sum(w.level != "low" for w in rare),
        "rare_windows": len(rare),
        "benign_max_R": benign_max,
        "sum_R_normal": sum(windows[k].risk for k in keys if not attack[k]),
        "nonzero_normal": sum(windows[k].risk > 0 for k in keys if not attack[k]),
        "thin_windows": sum("thin_baseline" in windows[k].facts for k in keys),
        "attack_R": sorted(round(windows[k].risk, 1) for k in keys if attack[k]),
    }


def facts_variant(kind):
    f = dict(CLOUD.facts)
    if kind == "equal":
        m = sum(f.values()) / len(f)
        f = {k: m for k in f}
    elif kind.startswith("x"):
        f = {k: v * float(kind[1:]) for k, v in f.items()}
    elif kind.startswith("drop:"):
        f.pop(kind[5:])
    return replace(CLOUD, facts=f)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("reports/thesis"))
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    res = {"base": run()}
    res["window"] = [run(window_min=m) for m in (15, 30)]
    res["days"] = [run(days=d) for d in (7, 10)]
    res["s"] = [run(s=v) for v in (1, 3, 5)]
    res["thin"] = [run(thin=t) for t in (25, 100)]
    res["facts"] = {
        k: run(model=facts_variant(k))
        for k in ("equal", "x0.5", "x1.5", "drop:no_mfa", "drop:old_key")
    }
    set_params()
    neg = res["base"]["windows"] - res["base"]["positive"]
    res["ci95_fpr"] = clopper_pearson(res["base"]["incident"]["fp"], neg)
    (a.out / "sensitivity.json").write_text(
        json.dumps(res, ensure_ascii=False, indent=1, default=str), encoding="utf-8"
    )

    def line(r):
        p = r["params"]
        i = r["incident"]
        h = r["high"]
        return f"{p} win={r['windows']} pos={r['positive']} inc TP{i['tp']} FP{i['fp']} F1={i['f1']:.3f} | high F1={h['f1']:.3f} | scen {r['scenarios_detected']}/{r['scenarios']} lat={r['latency_mean_min']:.0f}/{r['latency_max_min']:.0f} | rare FP {r['rare_fp']}/{r['rare_windows']} | benignMax {r['benign_max_R']:.1f} | sumRn {r['sum_R_normal']:.0f} nz {r['nonzero_normal']} thin {r['thin_windows']} | atk {r['attack_R']}"

    print("BASE", line(res["base"]))
    for g in ("window", "days", "s", "thin"):
        for r in res[g]:
            print(g, line(r))
    for k, r in res["facts"].items():
        print("facts", k, line(r))
    print(
        "95 % інтервал частки хибних спрацювань:",
        res["ci95_fpr"],
        "вікон без атак:",
        neg,
    )
