"""Rule-based authentication threat detections."""

from __future__ import annotations

from collections import Counter, deque
from pathlib import Path

import pandas as pd

from parser import load_security_logs


ALERT_COLUMNS = (
    "timestamp",
    "alert_type",
    "source_ip",
    "username",
    "failed_attempts",
    "severity",
    "mitre_technique",
    "description",
)

DETECTION_COLUMNS = {"timestamp", "source_ip", "username", "event_type"}


def _prepare_logs(df: pd.DataFrame) -> pd.DataFrame:
    """Return a chronological copy with detection-ready timestamps."""
    missing = sorted(DETECTION_COLUMNS.difference(df.columns))
    if missing:
        raise ValueError("Missing detection columns: " + ", ".join(missing))

    logs = df.copy()
    logs["timestamp"] = pd.to_datetime(
        logs["timestamp"], format="mixed", errors="coerce", utc=True
    )
    logs = logs.dropna(subset=list(DETECTION_COLUMNS))
    return logs.sort_values("timestamp").reset_index(drop=True)


def _alert_frame(alerts: list[dict[str, object]]) -> pd.DataFrame:
    """Create an alert DataFrame with a consistent schema."""
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def detect_brute_force(df: pd.DataFrame) -> pd.DataFrame:
    """Detect five failures against one user from one IP within two minutes."""
    failures = _prepare_logs(df).query("event_type == 'LOGIN_FAILED'")
    window = pd.Timedelta(minutes=2)
    alerts: list[dict[str, object]] = []

    for (source_ip, username), group in failures.groupby(
        ["source_ip", "username"], sort=False
    ):
        recent: deque[pd.Timestamp] = deque()
        previous: pd.Timestamp | None = None
        episode_alerted = False

        for timestamp in group["timestamp"]:
            if previous is None or timestamp - previous > window:
                recent.clear()
                episode_alerted = False
            while recent and timestamp - recent[0] > window:
                recent.popleft()
            recent.append(timestamp)

            if len(recent) >= 5 and not episode_alerted:
                alerts.append(
                    {
                        "timestamp": timestamp,
                        "alert_type": "Brute Force",
                        "source_ip": source_ip,
                        "username": username,
                        "failed_attempts": len(recent),
                        "severity": "HIGH",
                        "mitre_technique": "T1110 - Brute Force",
                        "description": (
                            f"{len(recent)} failed logins from {source_ip} targeted "
                            f"{username} within 2 minutes."
                        ),
                    }
                )
                episode_alerted = True
            previous = timestamp

    return _alert_frame(alerts)


def detect_password_spraying(df: pd.DataFrame) -> pd.DataFrame:
    """Detect one IP failing against five unique users within five minutes."""
    failures = _prepare_logs(df).query("event_type == 'LOGIN_FAILED'")
    window = pd.Timedelta(minutes=5)
    alerts: list[dict[str, object]] = []

    for source_ip, group in failures.groupby("source_ip", sort=False):
        recent: deque[tuple[pd.Timestamp, str]] = deque()
        user_counts: Counter[str] = Counter()
        previous: pd.Timestamp | None = None
        episode_alerted = False

        for row in group.itertuples(index=False):
            if previous is None or row.timestamp - previous > window:
                recent.clear()
                user_counts.clear()
                episode_alerted = False

            while recent and row.timestamp - recent[0][0] > window:
                _, expired_user = recent.popleft()
                user_counts[expired_user] -= 1
                if user_counts[expired_user] == 0:
                    del user_counts[expired_user]

            recent.append((row.timestamp, row.username))
            user_counts[row.username] += 1

            if len(user_counts) >= 5 and not episode_alerted:
                alerts.append(
                    {
                        "timestamp": row.timestamp,
                        "alert_type": "Password Spraying",
                        "source_ip": source_ip,
                        "username": pd.NA,
                        "failed_attempts": len(recent),
                        "severity": "HIGH",
                        "mitre_technique": "T1110.003 - Password Spraying",
                        "description": (
                            f"{source_ip} generated {len(recent)} failed logins "
                            f"against {len(user_counts)} users within 5 minutes."
                        ),
                    }
                )
                episode_alerted = True
            previous = row.timestamp

    return _alert_frame(alerts)


def detect_suspicious_successful_authentication(df: pd.DataFrame) -> pd.DataFrame:
    """Detect a success after five failures for the same IP/user in ten minutes."""
    logs = _prepare_logs(df)
    logs = logs.loc[logs["event_type"].isin(["LOGIN_FAILED", "LOGIN_SUCCESS"])]
    window = pd.Timedelta(minutes=10)
    alerts: list[dict[str, object]] = []

    for (source_ip, username), group in logs.groupby(
        ["source_ip", "username"], sort=False
    ):
        recent_failures: deque[pd.Timestamp] = deque()

        for row in group.itertuples(index=False):
            while recent_failures and row.timestamp - recent_failures[0] > window:
                recent_failures.popleft()

            if row.event_type == "LOGIN_FAILED":
                recent_failures.append(row.timestamp)
            elif len(recent_failures) >= 5:
                alerts.append(
                    {
                        "timestamp": row.timestamp,
                        "alert_type": "Suspicious Successful Authentication",
                        "source_ip": source_ip,
                        "username": username,
                        "failed_attempts": len(recent_failures),
                        "severity": "CRITICAL",
                        "mitre_technique": "T1110 - Brute Force",
                        "description": (
                            f"{source_ip} logged into {username} after "
                            f"{len(recent_failures)} failures within 10 minutes."
                        ),
                    }
                )
                recent_failures.clear()

    return _alert_frame(alerts)


def run_all_detections(df: pd.DataFrame) -> pd.DataFrame:
    """Run all rules and return one deduplicated chronological alert table."""
    alerts = pd.concat(
        [
            detect_brute_force(df),
            detect_password_spraying(df),
            detect_suspicious_successful_authentication(df),
        ],
        ignore_index=True,
    )
    if alerts.empty:
        return _alert_frame([])

    return (
        alerts.drop_duplicates(
            subset=["timestamp", "alert_type", "source_ip", "username"]
        )
        .sort_values("timestamp", kind="stable")
        .reset_index(drop=True)
    )


if __name__ == "__main__":
    print("Running detector...")
    data_path = Path(__file__).resolve().parent / "data" / "security_logs.csv"
    logs_df = load_security_logs(data_path)
    detected_alerts = run_all_detections(logs_df)

    print(f"Total alerts: {len(detected_alerts):,}")
    print("\nAlert counts by type:")
    print(detected_alerts["alert_type"].value_counts())
    print("\nAlert counts by severity:")
    print(detected_alerts["severity"].value_counts())
    print("\nFirst 10 alerts:")
    print(detected_alerts.head(10))
