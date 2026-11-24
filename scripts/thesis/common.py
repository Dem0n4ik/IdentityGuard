"""Спільні функції для відтворення таблиць магістерської роботи."""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import date

END_DAY = date(2026, 11, 15)
"""Останній день періоду оцінювання, на якому отримано результати розділу 3."""

SEED = 20260117
"""Початкове значення генератора (зафіксоване в app.devdata)."""


def prf(pairs: list[tuple[bool, bool]]) -> dict[str, float]:
    """Матриця помилок і метрики для пар (виявлено, атака)."""
    tp = sum(d and a for d, a in pairs)
    fp = sum(d and not a for d, a in pairs)
    fn = sum(a and not d for d, a in pairs)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "f1": 2 * tp / (2 * tp + fp + fn) if tp else 0.0,
    }


def roc_auc(pos: list[float], neg: list[float]) -> float:
    return sum((a > n) + 0.5 * (a == n) for a in pos for n in neg) / (
        len(pos) * len(neg)
    )


def pr_auc(scores: list[float], labels: list[bool]) -> float:
    """Середня влучність з групуванням однакових оцінок."""
    pairs = sorted(zip(scores, labels), key=lambda x: -x[0])
    total = sum(labels)
    tp = fp = 0
    prev_recall = area = 0.0
    i = 0
    while i < len(pairs):
        j = i
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            j += 1
        tp += sum(lab for _, lab in pairs[i:j])
        fp += sum(not lab for _, lab in pairs[i:j])
        recall = tp / total
        area += (recall - prev_recall) * tp / (tp + fp)
        prev_recall = recall
        i = j
    return area


def _binom_cdf(k: int, n: int, p: float) -> float:
    return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k + 1))


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Точний довірчий інтервал для частки k/n (бісекція за біноміальним розподілом)."""

    def solve(target: float, kk: int) -> float:
        lo, hi = 0.0, 1.0
        for _ in range(100):
            mid = (lo + hi) / 2
            if _binom_cdf(kk, n, mid) > target:
                lo = mid
            else:
                hi = mid
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else solve(1 - alpha / 2, k - 1)
    upper = 1.0 if k == n else solve(alpha / 2, k)
    return lower, upper


def window_labels(events, labels):  # type: ignore[no-untyped-def]
    """Мітки сценаріїв для кожного годинного вікна (ідентичність, година)."""
    out = defaultdict(set)
    for event in events:
        if event.identity is not None and event.event_id in labels:
            out[event.identity, event.hour].add(labels[event.event_id])
    return out
