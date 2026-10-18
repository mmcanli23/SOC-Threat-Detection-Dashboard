"""Explainable rule-based risk scoring for SOC alerts."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pandas as pd


BASE_SCORES = {
    "Brute Force": 65,
    "Password Spraying": 70,
    "Suspicious Successful Authentication": 85,
}

SEVERITY_BONUSES = {
    "LOW": 0,
    "MEDIUM": 2,
    "HIGH": 4,
    "CRITICAL": 6,
}


def _get_value(alert: Mapping[str, Any] | pd.Series, key: str, default: Any = None) -> Any:
    """Read an alert value without failing on absent or null fields."""
    value = alert.get(key, default)
    try:
        return default if pd.isna(value) else value
    except (TypeError, ValueError):
        # List-like optional fields make pd.isna return an array.
        return value


def _safe_number(value: Any, default: float = 0.0) -> float:
    """Convert a possible numeric value while safely handling bad input."""
    try:
        number = float(value)
        return default if pd.isna(number) else max(number, 0.0)
    except (TypeError, ValueError):
        return default


def _is_true(value: Any) -> bool:
    """Interpret common boolean representations defensively."""
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "successful"}
    return bool(value) if value is not None else False


def _unique_user_count(alert: Mapping[str, Any] | pd.Series) -> int:
    """Get a unique-target count from any supported optional alert field."""
    for field in ("unique_usernames_targeted", "unique_users", "unique_usernames"):
        value = _get_value(alert, field)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            return len(set(value))
        return int(_safe_number(value))
    return 0


def _frequency_bonus(alert: Mapping[str, Any] | pd.Series, failed_attempts: float) -> int:
    """Score optional event-rate data when a detector provides it."""
    if _is_true(_get_value(alert, "rapid_activity", False)):
        return 10

    events_per_minute = _safe_number(_get_value(alert, "events_per_minute"))
    if not events_per_minute:
        duration_seconds = _safe_number(_get_value(alert, "activity_duration_seconds"))
        if duration_seconds > 0:
            events_per_minute = failed_attempts / (duration_seconds / 60)

    if events_per_minute >= 30:
        return 10
    if events_per_minute >= 10:
        return 5
    return 0


def get_risk_level(score: int | float) -> str:
    """Convert a numeric risk score into LOW, MEDIUM, HIGH, or CRITICAL."""
    normalized_score = min(max(_safe_number(score), 0), 100)
    if normalized_score >= 80:
        return "CRITICAL"
    if normalized_score >= 60:
        return "HIGH"
    if normalized_score >= 40:
        return "MEDIUM"
    return "LOW"


def calculate_risk_score(alert: Mapping[str, Any] | pd.Series) -> int:
    """Calculate a transparent 0-100 score for one alert.

    The score starts with the alert-type base value, then adds bounded bonuses
    for attack volume, breadth, successful compromise, speed, and severity.
    Optional fields are ignored when absent rather than causing an exception.
    """
    alert_type = str(_get_value(alert, "alert_type", "Unknown"))
    score = BASE_SCORES.get(alert_type, 20)

    failed_attempts = _safe_number(_get_value(alert, "failed_attempts"))
    if failed_attempts >= 20:
        score += 15
    elif failed_attempts >= 10:
        score += 10
    elif failed_attempts >= 5:
        score += 5

    unique_users = _unique_user_count(alert)
    # A password-spraying alert guarantees at least five unique targets even
    # when the detector's current output does not include the optional count.
    if alert_type == "Password Spraying" and unique_users == 0:
        unique_users = 5
    if unique_users >= 20:
        score += 15
    elif unique_users >= 10:
        score += 10
    elif unique_users >= 5:
        score += 5

    successful_after_failures = alert_type == "Suspicious Successful Authentication"
    successful_after_failures = successful_after_failures or _is_true(
        _get_value(alert, "successful_login_after_failures", False)
    )
    if successful_after_failures:
        score += 10

    score += _frequency_bonus(alert, failed_attempts)

    severity = str(_get_value(alert, "severity", "LOW")).upper()
    score += SEVERITY_BONUSES.get(severity, 0)

    return min(int(round(score)), 100)


def score_alerts(alerts_df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of an alert DataFrame with risk score and level columns."""
    if not isinstance(alerts_df, pd.DataFrame):
        raise TypeError("alerts_df must be a pandas DataFrame")

    scored_alerts = alerts_df.copy()
    if scored_alerts.empty:
        scored_alerts["risk_score"] = pd.Series(dtype="int64")
        scored_alerts["risk_level"] = pd.Series(dtype="string")
        return scored_alerts

    scored_alerts["risk_score"] = scored_alerts.apply(calculate_risk_score, axis=1)
    scored_alerts["risk_level"] = scored_alerts["risk_score"].map(get_risk_level)
    return scored_alerts


if __name__ == "__main__":
    from detector import run_all_detections
    from parser import load_security_logs

    data_path = Path(__file__).resolve().parent / "data" / "security_logs.csv"
    logs = load_security_logs(data_path)
    alerts = run_all_detections(logs)
    scored = score_alerts(alerts)

    print(f"Total scored alerts: {len(scored):,}")
    print("\nRisk level counts:")
    print(scored["risk_level"].value_counts())
    print("\nFirst 10 scored alerts:")
    display_columns = ["alert_type", "source_ip", "risk_score", "risk_level"]
    print(scored.loc[:, display_columns].head(10))
