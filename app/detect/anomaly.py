"""
Unsupervised anomaly detection over event telemetry.

Isolation Forest, trained on whatever normal traffic the deployment has seen.
It is deliberately a *ranking* aid: it raises "this is unlike the baseline",
not "this is malicious". A statistical outlier still needs a rule or an analyst
to become an alert, which is why the score is blended rather than trusted.

The whole scientific stack is optional. Without scikit-learn installed, the
model falls back to a robust z-score baseline written in plain Python, so the
core install stays small and the API behaves identically — only the quality of
the ranking changes. Install the extra with:

    pip install -r requirements-ml.txt
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime

try:  # the scientific stack is an optional extra
    import numpy as np
    from sklearn.ensemble import IsolationForest

    HAVE_SKLEARN = True
except Exception:  # pragma: no cover - exercised only when the wheels are absent
    HAVE_SKLEARN = False

FEATURES = ("bytes_out", "bytes_in", "duration_ms", "ratio", "hour", "payload_entropy")
MIN_TRAINING_ROWS = 40

# A feature that never varied in training has a near-zero deviation, which
# would turn any new value into a millions-of-sigma reading. Both bounds below
# keep the explanation honest: floor the spread, then cap what we report.
Z_CAP = 50.0

# Deviation at which an event is worth an analyst's attention. The score curve
# is anchored so that exactly this many sigma maps to 0.85 — the threshold the
# alerting path uses — and every larger deviation still ranks above it instead
# of flat-lining at 1.0, which is what makes the queue sortable.
Z_ALERT = 6.0


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def featurize(event: dict) -> list[float]:
    out = float(event.get("bytes_out") or 0)
    inn = float(event.get("bytes_in") or 0)
    dur = float(event.get("duration_ms") or 0)
    ts = event.get("received_at")
    hour = ts.hour if isinstance(ts, datetime) else 12
    return [
        math.log1p(out),
        math.log1p(inn),
        math.log1p(dur),
        math.log1p(out / (inn + 1.0)),   # log-scaled: ratios are heavy-tailed
        float(hour),
        _entropy(str(event.get("payload") or "")),
    ]


def _saturate(z: float) -> float:
    """Map a sigma distance to 0-1, strictly increasing, 6σ → 0.85."""
    return round(1 - 0.15 ** (z / Z_ALERT), 4)


def _mean(col: list[float]) -> float:
    return sum(col) / len(col)


def _stdev(col: list[float], mean: float) -> float:
    if len(col) < 2:
        return 0.0
    return math.sqrt(sum((x - mean) ** 2 for x in col) / len(col))


@dataclass
class AnomalyModel:
    contamination: float = 0.06
    _model: object | None = None
    _mean: list[float] | None = None
    _std: list[float] | None = None
    trained_on: int = 0
    feature_names: tuple[str, ...] = field(default=FEATURES)

    @property
    def is_trained(self) -> bool:
        return self._model is not None or self._mean is not None

    @property
    def backend(self) -> str:
        if self._model is not None:
            return "isolation-forest"
        return "z-score" if self._mean is not None else "untrained"

    def fit(self, events: list[dict]) -> AnomalyModel:
        rows = [featurize(e) for e in events]
        if len(rows) < 5:
            return self
        self.trained_on = len(rows)

        if HAVE_SKLEARN and len(rows) >= MIN_TRAINING_ROWS:
            self._model = IsolationForest(
                n_estimators=180,
                contamination=self.contamination,
                random_state=1337,
                n_jobs=1,
            ).fit(np.array(rows, dtype=float))
            self._mean = self._std = None
        else:
            # Robust z-score baseline: works from the very first handful of rows.
            self._model = None
            cols = [list(c) for c in zip(*rows, strict=True)]
            self._mean = [_mean(c) for c in cols]
            self._std = [
                max(_stdev(c, m), 0.05 * max(1.0, abs(m)))
                for c, m in zip(cols, self._mean, strict=True)
            ]
        return self

    def _z(self, vec: list[float]) -> list[float]:
        if self._mean is None or self._std is None:  # pragma: no cover - guarded by callers
            raise RuntimeError("anomaly model has no baseline yet")
        return [
            min(Z_CAP, abs((v - m) / s))
            for v, m, s in zip(vec, self._mean, self._std, strict=True)
        ]

    def score(self, event: dict) -> float:
        """0-1, higher is stranger."""
        vec = featurize(event)
        if self._model is not None:
            # decision_function: positive = inlier. Map to 0-1 with a soft curve.
            raw = float(self._model.decision_function(np.array([vec], dtype=float))[0])
            return round(float(1 / (1 + math.exp(raw * 6))), 4)
        if self._mean is not None:
            return _saturate(max(self._z(vec)))
        return 0.0

    def explain(self, event: dict) -> list[str]:
        """Which features made this event stand out — analysts need the why."""
        if self._mean is None:
            if self._model is not None:
                return ["isolated early by the forest (unusual combination of features)"]
            return []
        z = self._z(featurize(event))
        reasons = []
        for name, score in sorted(zip(self.feature_names, z, strict=True), key=lambda p: -p[1])[:3]:
            if score >= Z_CAP:
                reasons.append(f"{name} is far outside baseline (>{Z_CAP:.0f}σ)")
            elif score > 2.0:
                reasons.append(f"{name} is {score:.1f}σ from baseline")
        return reasons
