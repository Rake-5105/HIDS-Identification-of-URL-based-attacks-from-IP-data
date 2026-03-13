from __future__ import annotations

import pandas as pd


def add_statistical_flags(
    df: pd.DataFrame,
    flood_threshold: int = 100,
    flood_window_seconds: int = 10,
    brute_force_threshold: int = 4,
    brute_force_window_seconds: int = 60,
) -> pd.DataFrame:
    if "source_ip" not in df.columns or "timestamp" not in df.columns:
        out = df.copy()
        out["stat_is_flood"] = 0
        out["stat_is_bruteforce"] = 0
        out["stat_suspicious"] = 0
        return out

    out = df.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce")
    if out["timestamp"].isna().all():
        out["stat_is_flood"] = 0
        out["stat_is_bruteforce"] = 0
        out["stat_suspicious"] = 0
        return out

    out["timestamp"] = out["timestamp"].fillna(pd.Timestamp("1970-01-01"))
    out = out.sort_values(["source_ip", "timestamp"]).reset_index(drop=True)

    out["_request_event"] = 1
    out["_is_login_attempt"] = (
        out.get("method", "").astype(str).str.upper().eq("POST")
        & out.get("path", "").astype(str).str.contains("login", case=False, na=False)
    ).astype(int)

    flood_counts = []
    brute_counts = []

    for _, group in out.groupby("source_ip", sort=False):
        g = group.set_index("timestamp")

        flood = g["_request_event"].rolling(f"{flood_window_seconds}s").sum().fillna(0)
        brute = g["_is_login_attempt"].rolling(f"{brute_force_window_seconds}s").sum().fillna(0)

        flood_counts.extend(flood.tolist())
        brute_counts.extend(brute.tolist())

    out["_flood_count_window"] = flood_counts
    out["_bruteforce_count_window"] = brute_counts

    out["stat_is_flood"] = (out["_flood_count_window"] >= flood_threshold).astype(int)
    out["stat_is_bruteforce"] = (out["_bruteforce_count_window"] >= brute_force_threshold).astype(int)
    out["stat_suspicious"] = ((out["stat_is_flood"] == 1) | (out["stat_is_bruteforce"] == 1)).astype(int)

    return out.drop(columns=["_request_event", "_is_login_attempt", "_flood_count_window", "_bruteforce_count_window"])
