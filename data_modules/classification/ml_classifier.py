from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from .regex_detector import detect_regex_attack


FEATURE_COLUMNS = [
    "url_length",
    "special_characters",
    "has_sql_keyword",
    "has_script",
    "has_traversal",
]

ATTACK_CLASSES = {
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Directory Traversal",
    "Suspicious Behavior",
}


@dataclass
class ModelArtifacts:
    model: RandomForestClassifier
    feature_columns: list[str]
    accuracy: float
    report_text: str


def _resolve_feature_columns(df: pd.DataFrame) -> list[str]:
    cols = [c for c in FEATURE_COLUMNS if c in df.columns]
    if not cols:
        raise ValueError("No Module-3 feature columns found in input dataset")
    return cols


def _weak_label(row: pd.Series, url_col: str) -> str:
    regex_class, _ = detect_regex_attack(row.get(url_col, ""))
    if regex_class != "Normal":
        return regex_class

    status_value = pd.to_numeric(row.get("status_code", 0), errors="coerce")
    status_code = int(status_value) if pd.notna(status_value) else 0
    user_agent = str(row.get("user_agent", "")).lower()

    if status_code >= 400 or any(x in user_agent for x in ["sqlmap", "nikto", "acunetix", "nmap"]):
        return "Suspicious Behavior"

    return "Normal"


def train_multiclass_model(df: pd.DataFrame, url_col: str, random_state: int = 42) -> ModelArtifacts:
    feature_cols = _resolve_feature_columns(df)

    X = df[feature_cols].fillna(0)
    y = df.apply(lambda r: _weak_label(r, url_col), axis=1)

    stratify_target = y if y.nunique() > 1 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=random_state,
        stratify=stratify_target,
    )

    model = RandomForestClassifier(
        n_estimators=250,
        max_depth=10,
        random_state=random_state,
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    accuracy = float(accuracy_score(y_test, preds))
    report_text = classification_report(y_test, preds, digits=4)

    return ModelArtifacts(
        model=model,
        feature_columns=feature_cols,
        accuracy=accuracy,
        report_text=report_text,
    )


def predict_with_model(df: pd.DataFrame, artifacts: ModelArtifacts) -> tuple[pd.Series, pd.Series]:
    X = df[artifacts.feature_columns].fillna(0)
    labels = artifacts.model.predict(X)

    probabilities = artifacts.model.predict_proba(X)
    confidence = probabilities.max(axis=1)

    return pd.Series(labels, index=df.index), pd.Series(confidence, index=df.index)


def save_model(artifacts: ModelArtifacts, output_dir: str) -> str:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    model_path = out_dir / "module4_rf_model.joblib"
    joblib.dump(
        {
            "model": artifacts.model,
            "feature_columns": artifacts.feature_columns,
            "accuracy": artifacts.accuracy,
        },
        model_path,
    )
    return str(model_path)
