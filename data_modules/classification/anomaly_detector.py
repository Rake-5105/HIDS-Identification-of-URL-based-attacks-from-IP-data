from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .ml_classifier import FEATURE_COLUMNS


ANOMALY_CONTAMINATION = 0.1


@dataclass
class AnomalyArtifacts:
    model: Pipeline | None
    feature_columns: list[str]
    contamination: float
    anomaly_rate: float
    threshold: float


def _resolve_feature_columns(df: pd.DataFrame) -> list[str]:
    cols = [c for c in FEATURE_COLUMNS if c in df.columns]
    if cols:
        return cols

    numeric_cols = df.select_dtypes(include=["number", "bool"]).columns.tolist()
    return [c for c in numeric_cols if c not in {"stat_is_flood", "stat_is_bruteforce", "stat_suspicious"}]


def train_isolation_forest(
    df: pd.DataFrame,
    contamination: float = ANOMALY_CONTAMINATION,
    random_state: int = 42,
) -> AnomalyArtifacts:
    feature_cols = _resolve_feature_columns(df)
    if not feature_cols or len(df) < 8:
        return AnomalyArtifacts(
            model=None,
            feature_columns=feature_cols,
            contamination=contamination,
            anomaly_rate=0.0,
            threshold=0.0,
        )

    X = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    if X.nunique(dropna=False).sum() <= len(feature_cols):
        return AnomalyArtifacts(
            model=None,
            feature_columns=feature_cols,
            contamination=contamination,
            anomaly_rate=0.0,
            threshold=0.0,
        )

    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "isolation_forest",
                IsolationForest(
                    n_estimators=200,
                    contamination=contamination,
                    random_state=random_state,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    model.fit(X)

    predictions = model.predict(X)
    anomaly_rate = float((predictions == -1).mean())
    decision_scores = model.decision_function(X)
    threshold = float(np.percentile(decision_scores, contamination * 100)) if len(decision_scores) else 0.0

    return AnomalyArtifacts(
        model=model,
        feature_columns=feature_cols,
        contamination=contamination,
        anomaly_rate=anomaly_rate,
        threshold=threshold,
    )


def score_with_isolation_forest(df: pd.DataFrame, artifacts: AnomalyArtifacts) -> tuple[pd.Series, pd.Series]:
    if artifacts.model is None or not artifacts.feature_columns:
        zeros = pd.Series([0] * len(df), index=df.index)
        scores = pd.Series([0.0] * len(df), index=df.index)
        return zeros, scores

    X = df[artifacts.feature_columns].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    predictions = artifacts.model.predict(X)
    decision_scores = artifacts.model.decision_function(X)

    anomaly_flag = pd.Series((predictions == -1).astype(int), index=df.index)
    anomaly_score = pd.Series((-decision_scores).astype(float), index=df.index)
    return anomaly_flag, anomaly_score


def save_anomaly_model(artifacts: AnomalyArtifacts, output_dir: str) -> str:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    model_path = out_dir / "module4_isolation_forest.joblib"
    joblib.dump(
        {
            "model": artifacts.model,
            "feature_columns": artifacts.feature_columns,
            "contamination": artifacts.contamination,
            "anomaly_rate": artifacts.anomaly_rate,
            "threshold": artifacts.threshold,
        },
        model_path,
    )
    return str(model_path)