"""Unit tests for the authentication detection rules."""

from __future__ import annotations

import pandas as pd
import pytest

from detector import (
    detect_brute_force,
    detect_password_spraying,
    detect_suspicious_successful_authentication,
    run_all_detections,
)


BASE_TIME = pd.Timestamp("2026-01-15 12:00:00", tz="UTC")


def make_event(
    minutes: float,
    source_ip: str,
    username: str,
    event_type: str,
) -> dict[str, object]:
    """Create one deterministic authentication event for a test DataFrame."""
    return {
        "timestamp": BASE_TIME + pd.Timedelta(minutes=minutes),
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
    }


def alert_types(alerts: pd.DataFrame) -> set[str]:
    """Return the alert types from a detector result."""
    return set(alerts["alert_type"].tolist())


def test_normal_activity_does_not_trigger_brute_force() -> None:
    """Successful logins and fewer than five failures should remain normal."""
    events = [
        make_event(0, "192.0.2.10", "alice", "LOGIN_SUCCESS"),
        make_event(0.2, "192.0.2.10", "alice", "LOGIN_FAILED"),
        make_event(0.4, "192.0.2.10", "alice", "LOGIN_FAILED"),
        make_event(0.6, "192.0.2.10", "alice", "LOGIN_FAILED"),
        make_event(0.8, "192.0.2.10", "alice", "LOGIN_FAILED"),
        make_event(1, "192.0.2.11", "bob", "LOGIN_SUCCESS"),
    ]

    alerts = detect_brute_force(pd.DataFrame(events))

    assert alerts.empty
    assert "Brute Force" not in alert_types(alerts)


def test_brute_force_triggers_for_five_rapid_failures() -> None:
    """Five failures for one IP/user pair within two minutes should alert."""
    events = [
        make_event(index * 0.25, "198.51.100.10", "admin", "LOGIN_FAILED")
        for index in range(5)
    ]

    alerts = detect_brute_force(pd.DataFrame(events))

    assert "Brute Force" in alert_types(alerts)
    assert alerts.iloc[0]["source_ip"] == "198.51.100.10"
    assert alerts.iloc[0]["username"] == "admin"
    assert alerts.iloc[0]["failed_attempts"] == 5


def test_brute_force_does_not_trigger_for_spread_out_failures() -> None:
    """Failures separated by more than two minutes should not be grouped."""
    events = [
        make_event(index * 3, "198.51.100.20", "carol", "LOGIN_FAILED")
        for index in range(5)
    ]

    alerts = detect_brute_force(pd.DataFrame(events))

    assert alerts.empty


def test_password_spraying_triggers_for_five_unique_users() -> None:
    """One IP failing against five users within five minutes should alert."""
    events = [
        make_event(index * 0.5, "203.0.113.25", f"user{index}", "LOGIN_FAILED")
        for index in range(5)
    ]

    alerts = detect_password_spraying(pd.DataFrame(events))

    assert "Password Spraying" in alert_types(alerts)
    assert alerts.iloc[0]["source_ip"] == "203.0.113.25"
    assert alerts.iloc[0]["severity"] == "HIGH"


def test_suspicious_successful_authentication_triggers() -> None:
    """A success after five recent failures for the same account should alert."""
    events = [
        make_event(index, "203.0.113.50", "dana", "LOGIN_FAILED")
        for index in range(5)
    ]
    events.append(make_event(5, "203.0.113.50", "dana", "LOGIN_SUCCESS"))

    alerts = detect_suspicious_successful_authentication(pd.DataFrame(events))

    assert "Suspicious Successful Authentication" in alert_types(alerts)
    assert alerts.iloc[0]["failed_attempts"] == 5
    assert alerts.iloc[0]["severity"] == "CRITICAL"


def test_failures_without_success_do_not_trigger_suspicious_success() -> None:
    """Repeated failures alone must not be labeled as a successful compromise."""
    events = [
        make_event(index, "203.0.113.60", "erin", "LOGIN_FAILED")
        for index in range(6)
    ]

    alerts = detect_suspicious_successful_authentication(pd.DataFrame(events))

    assert alerts.empty


def test_run_all_detections_returns_dataframe() -> None:
    """The combined detector should always return a pandas DataFrame."""
    events = [
        make_event(index * 0.25, "198.51.100.30", "frank", "LOGIN_FAILED")
        for index in range(5)
    ]

    alerts = run_all_detections(pd.DataFrame(events))

    assert isinstance(alerts, pd.DataFrame)


def test_alerts_include_expected_fields() -> None:
    """Detector output must provide the fields consumed by scoring and the UI."""
    events = [
        make_event(index * 0.25, "198.51.100.40", "grace", "LOGIN_FAILED")
        for index in range(5)
    ]
    expected_fields = {
        "timestamp",
        "alert_type",
        "source_ip",
        "username",
        "severity",
        "mitre_technique",
        "description",
    }

    alerts = run_all_detections(pd.DataFrame(events))

    assert not alerts.empty
    assert expected_fields.issubset(alerts.columns)


@pytest.mark.parametrize(
    ("minutes", "expected_level"),
    [([0, 0.25, 0.5, 0.75, 1], True), ([0, 3, 6, 9, 12], False)],
)
def test_brute_force_window_boundary(
    minutes: list[float], expected_level: bool
) -> None:
    """The two-minute window should consistently separate rapid and slow activity."""
    events = [
        make_event(minute, "192.0.2.99", "window-test", "LOGIN_FAILED")
        for minute in minutes
    ]

    alerts = detect_brute_force(pd.DataFrame(events))

    assert (not alerts.empty) is expected_level
