"""Streamlit dashboard for authentication threat monitoring and investigation."""

from __future__ import annotations

import hashlib
import time
from io import BytesIO
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from detector import run_all_detections
from parser import REQUIRED_COLUMNS, load_security_logs
from risk_scoring import get_risk_level, score_alerts


DATA_PATH = Path(__file__).resolve().parent / "data" / "security_logs.csv"

SEVERITY_COLORS = {
    "LOW": "#22c55e",
    "MEDIUM": "#eab308",
    "HIGH": "#f97316",
    "CRITICAL": "#dc2626",
}

ALERT_TABLE_COLUMNS = [
    "timestamp",
    "alert_type",
    "source_ip",
    "username",
    "severity",
    "risk_score",
    "risk_level",
    "mitre_technique",
    "description",
]


st.set_page_config(
    page_title="SOC Threat Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_data(show_spinner=False)
def run_security_pipeline(logs: pd.DataFrame) -> pd.DataFrame:
    """Run the existing detector and risk scorer for the active events."""
    alerts = run_all_detections(logs)
    return score_alerts(alerts)


@st.cache_data(show_spinner=False)
def load_default_logs(file_path: str) -> pd.DataFrame:
    """Load and normalize the generated on-disk dataset."""
    return load_security_logs(file_path)


@st.cache_data(show_spinner=False)
def load_uploaded_logs(file_bytes: bytes) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Read an uploaded CSV and clean it directly from memory."""
    raw = pd.read_csv(BytesIO(file_bytes), keep_default_na=False)
    missing_columns = [column for column in REQUIRED_COLUMNS if column not in raw]
    if missing_columns:
        raise ValueError("Missing required columns: " + ", ".join(missing_columns))

    cleaned = load_security_logs(BytesIO(file_bytes))
    return raw, cleaned


def sorted_options(df: pd.DataFrame, column: str) -> list[str]:
    """Return clean, sorted filter options for an optional DataFrame column."""
    if column not in df.columns or df.empty:
        return []
    values = df[column].dropna().astype(str)
    return sorted(value for value in values.unique().tolist() if value)


def apply_alert_filters(
    alerts: pd.DataFrame,
    severities: list[str],
    risk_levels: list[str],
    alert_types: list[str],
    source_ips: list[str],
    usernames: list[str],
) -> pd.DataFrame:
    """Apply sidebar selections without assuming every optional column exists."""
    filtered = alerts.copy()
    filters = {
        "severity": severities,
        "risk_level": risk_levels,
        "alert_type": alert_types,
        "source_ip": source_ips,
        "username": usernames,
    }
    for column, selected_values in filters.items():
        if column in filtered.columns:
            filtered = filtered.loc[
                filtered[column].astype("string").isin(selected_values)
            ]
    return filtered.reset_index(drop=True)


def initialize_live_state(dataset_key: str) -> None:
    """Create or reset simulation state when the active dataset changes."""
    if st.session_state.get("live_dataset_key") != dataset_key:
        st.session_state.live_dataset_key = dataset_key
        st.session_state.live_processed = 0
        st.session_state.live_running = False
        st.session_state.live_last_tick = time.monotonic()
        st.session_state.live_seen_alerts = set()


def advance_live_progress(total_events: int, events_per_second: int) -> int:
    """Advance a non-blocking simulation based on elapsed wall-clock time."""
    processed = int(st.session_state.get("live_processed", 0))
    if not st.session_state.get("live_running", False):
        return min(processed, total_events)

    now = time.monotonic()
    last_tick = float(st.session_state.get("live_last_tick", now))
    elapsed = max(now - last_tick, 0)
    new_events = int(elapsed * events_per_second)

    if new_events > 0:
        processed = min(processed + new_events, total_events)
        st.session_state.live_processed = processed
        st.session_state.live_last_tick = now

    if processed >= total_events:
        st.session_state.live_running = False
    return processed


def render_source_indicator(source_label: str, live_enabled: bool) -> None:
    """Show analysts which dataset and operating mode are currently active."""
    mode = "Simulated Live Monitoring" if live_enabled else "Static Analysis"
    st.info(f"**Data Source:** {source_label}  ·  **Mode:** {mode}")


def render_raw_preview(raw: pd.DataFrame, filename: str) -> None:
    """Preview uploaded rows and basic timestamp coverage before analysis."""
    with st.expander("Uploaded Data Preview"):
        st.write(f"**Filename:** `{filename}`")
        timestamps = pd.to_datetime(
            raw.get("timestamp", pd.Series(dtype="string")),
            format="mixed",
            errors="coerce",
            utc=True,
        )
        valid_timestamps = timestamps.dropna()
        earliest = valid_timestamps.min() if not valid_timestamps.empty else "Unavailable"
        latest = valid_timestamps.max() if not valid_timestamps.empty else "Unavailable"

        columns = st.columns(4)
        columns[0].metric("Rows", f"{len(raw):,}")
        columns[1].metric("Columns", f"{len(raw.columns):,}")
        columns[2].metric("Earliest Timestamp", str(earliest))
        columns[3].metric("Latest Timestamp", str(latest))

        st.write("**Event Type Counts**")
        if "event_type" in raw.columns:
            event_counts = (
                raw["event_type"]
                .fillna("Missing")
                .astype(str)
                .value_counts(dropna=False)
                .rename_axis("event_type")
                .reset_index(name="events")
            )
            st.dataframe(event_counts, hide_index=True, width="stretch")
        else:
            st.info("Event type counts are unavailable because the column is missing.")

        st.write("**First 20 Rows**")
        st.dataframe(raw.head(20), hide_index=True, width="stretch")


def alert_fingerprints(alerts: pd.DataFrame) -> set[tuple[str, ...]]:
    """Create stable alert identifiers for detecting newly surfaced alerts."""
    fingerprint_columns = ["timestamp", "alert_type", "source_ip", "username"]
    available = [column for column in fingerprint_columns if column in alerts]
    if alerts.empty or not available:
        return set()
    return {
        tuple(str(value) for value in row)
        for row in alerts.loc[:, available].itertuples(index=False, name=None)
    }


def render_live_alert_feed(alerts: pd.DataFrame) -> None:
    """Render newest alerts first and emphasize new high-priority detections."""
    st.header("Live Alert Feed")
    current_fingerprints = alert_fingerprints(alerts)
    previous_fingerprints = st.session_state.get("live_seen_alerts", set())
    new_fingerprints = current_fingerprints.difference(previous_fingerprints)

    if new_fingerprints and not alerts.empty:
        priority_mask = pd.Series(False, index=alerts.index)
        if "severity" in alerts:
            priority_mask |= alerts["severity"].isin(["HIGH", "CRITICAL"])
        if "risk_level" in alerts:
            priority_mask |= alerts["risk_level"].isin(["HIGH", "CRITICAL"])
        priority_alerts = alerts.loc[priority_mask]
        priority_keys = alert_fingerprints(priority_alerts)
        new_priority_count = len(new_fingerprints.intersection(priority_keys))
        if new_priority_count:
            st.error(
                f"New high-priority activity detected: "
                f"{new_priority_count} HIGH/CRITICAL alert(s)."
            )

    st.session_state.live_seen_alerts = current_fingerprints
    if alerts.empty:
        st.info("No alerts have been detected in the processed events yet.")
        return

    feed_columns = [
        column
        for column in (
            "timestamp",
            "alert_type",
            "source_ip",
            "username",
            "risk_score",
            "risk_level",
            "mitre_technique",
        )
        if column in alerts
    ]
    newest = alerts.sort_values("timestamp", ascending=False).loc[:, feed_columns]
    st.dataframe(newest.head(25), hide_index=True, width="stretch")


def render_how_it_works() -> None:
    """Explain the dashboard pipeline and the scope of live simulation."""
    with st.expander("How This Works"):
        st.markdown(
            """
1. Authentication logs are loaded from the generated dataset or an uploaded CSV.
2. `parser.py` validates, cleans, normalizes, and orders the events.
3. `detector.py` identifies suspicious authentication patterns.
4. `risk_scoring.py` assigns explainable risk scores and levels.
5. `app.py` presents alerts, trends, filters, and investigation details.

Live mode is a demonstration that progressively reveals existing events. It is
not connected to a production SIEM or real-time corporate data source.
            """
        )


def show_empty_chart(message: str) -> None:
    """Display a consistent explanation when a chart has no matching data."""
    st.info(message)


def render_metrics(logs: pd.DataFrame, alerts: pd.DataFrame) -> None:
    """Render top-level event and alert metrics."""
    failed_logins = int((logs["event_type"] == "LOGIN_FAILED").sum())
    successful_logins = int((logs["event_type"] == "LOGIN_SUCCESS").sum())
    critical_alerts = (
        int((alerts["risk_level"] == "CRITICAL").sum())
        if "risk_level" in alerts.columns
        else 0
    )

    columns = st.columns(5)
    columns[0].metric("Total Events", f"{len(logs):,}")
    columns[1].metric("Failed Logins", f"{failed_logins:,}")
    columns[2].metric("Successful Logins", f"{successful_logins:,}")
    columns[3].metric("Total Security Alerts", f"{len(alerts):,}")
    columns[4].metric("Critical Alerts", f"{critical_alerts:,}")


def render_alert_table(alerts: pd.DataFrame) -> None:
    """Show a defensive alert table containing only available columns."""
    st.subheader("Security Alerts")
    if alerts.empty:
        st.info("No alerts match the current filters.")
        return

    available_columns = [column for column in ALERT_TABLE_COLUMNS if column in alerts]
    st.dataframe(
        alerts.loc[:, available_columns],
        hide_index=True,
        width="stretch",
        column_config={
            "timestamp": st.column_config.DatetimeColumn(
                "Timestamp", format="YYYY-MM-DD HH:mm:ss"
            ),
            "risk_score": st.column_config.ProgressColumn(
                "Risk Score", min_value=0, max_value=100, format="%d"
            ),
        },
    )


def render_alert_charts(alerts: pd.DataFrame) -> None:
    """Render severity and alert-type summaries for filtered alerts."""
    left, right = st.columns(2)

    with left:
        st.subheader("Alerts by Severity")
        if alerts.empty or "severity" not in alerts:
            show_empty_chart("No severity data is available for the current filters.")
        else:
            severity_counts = (
                alerts["severity"]
                .value_counts()
                .rename_axis("severity")
                .reset_index(name="alerts")
            )
            figure = px.bar(
                severity_counts,
                x="severity",
                y="alerts",
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
                category_orders={"severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            )
            figure.update_layout(showlegend=False, xaxis_title=None, yaxis_title="Alerts")
            st.plotly_chart(figure, width="stretch", theme="streamlit")

    with right:
        st.subheader("Alert Types")
        if alerts.empty or "alert_type" not in alerts:
            show_empty_chart("No alert-type data is available for the current filters.")
        else:
            type_counts = (
                alerts["alert_type"]
                .value_counts()
                .rename_axis("alert_type")
                .reset_index(name="alerts")
            )
            figure = px.bar(
                type_counts,
                x="alerts",
                y="alert_type",
                orientation="h",
                color="alerts",
                color_continuous_scale="OrRd",
            )
            figure.update_layout(
                coloraxis_showscale=False,
                xaxis_title="Alerts",
                yaxis_title=None,
            )
            st.plotly_chart(figure, width="stretch", theme="streamlit")


def render_activity_charts(logs: pd.DataFrame) -> None:
    """Render failed-login trends and the most active targets."""
    failed = logs.loc[logs["event_type"] == "LOGIN_FAILED"].copy()

    st.subheader("Failed Login Activity Over Time")
    if failed.empty:
        show_empty_chart("No failed login events are available.")
    else:
        timeline = (
            failed.set_index("timestamp")
            .resample("h")
            .size()
            .rename("failed_logins")
            .reset_index()
        )
        figure = px.line(
            timeline,
            x="timestamp",
            y="failed_logins",
            markers=True,
        )
        figure.update_traces(line_color="#ef4444")
        figure.update_layout(xaxis_title=None, yaxis_title="Failed Logins")
        st.plotly_chart(figure, width="stretch", theme="streamlit")

    left, right = st.columns(2)
    with left:
        st.subheader("Top Source IPs Generating Failed Logins")
        if failed.empty:
            show_empty_chart("No failed-login source IPs are available.")
        else:
            top_ips = (
                failed["source_ip"]
                .value_counts()
                .head(10)
                .rename_axis("source_ip")
                .reset_index(name="failed_logins")
            )
            figure = px.bar(
                top_ips,
                x="failed_logins",
                y="source_ip",
                orientation="h",
                color="failed_logins",
                color_continuous_scale="Reds",
            )
            figure.update_layout(
                coloraxis_showscale=False,
                xaxis_title="Failed Logins",
                yaxis_title=None,
                yaxis={"categoryorder": "total ascending"},
            )
            st.plotly_chart(figure, width="stretch", theme="streamlit")

    with right:
        st.subheader("Most Targeted Usernames")
        if failed.empty:
            show_empty_chart("No targeted usernames are available.")
        else:
            top_users = (
                failed["username"]
                .value_counts()
                .head(10)
                .rename_axis("username")
                .reset_index(name="failed_logins")
            )
            figure = px.bar(
                top_users,
                x="failed_logins",
                y="username",
                orientation="h",
                color="failed_logins",
                color_continuous_scale="Blues",
            )
            figure.update_layout(
                coloraxis_showscale=False,
                xaxis_title="Failed Logins",
                yaxis_title=None,
                yaxis={"categoryorder": "total ascending"},
            )
            st.plotly_chart(figure, width="stretch", theme="streamlit")


def render_mitre_section(alerts: pd.DataFrame) -> None:
    """Summarize MITRE ATT&CK techniques represented by filtered alerts."""
    st.subheader("MITRE ATT&CK Techniques")
    if alerts.empty or "mitre_technique" not in alerts:
        st.info("No MITRE ATT&CK techniques match the current filters.")
        return

    technique_summary = (
        alerts.groupby("mitre_technique", dropna=False)
        .agg(
            alert_count=("mitre_technique", "size"),
            alert_types=("alert_type", lambda values: ", ".join(sorted(set(values)))),
        )
        .reset_index()
        .sort_values("alert_count", ascending=False)
    )
    st.dataframe(technique_summary, hide_index=True, width="stretch")


def render_investigation(logs: pd.DataFrame, alerts: pd.DataFrame) -> None:
    """Provide an analyst-focused drill-down for one selected source IP."""
    st.header("Source IP Investigation")
    source_ips = sorted_options(logs, "source_ip")
    if not source_ips:
        st.info("No source IPs are available for investigation.")
        return

    selected_ip = st.selectbox("Select a source IP", source_ips)
    ip_events = logs.loc[logs["source_ip"].astype(str) == selected_ip].copy()
    ip_alerts = (
        alerts.loc[alerts["source_ip"].astype(str) == selected_ip].copy()
        if "source_ip" in alerts
        else pd.DataFrame()
    )

    if not ip_alerts.empty and "risk_score" in ip_alerts:
        risk_scores = pd.to_numeric(ip_alerts["risk_score"], errors="coerce").fillna(0)
        risk_score = int(risk_scores.max())
    else:
        risk_score = 0
    risk_level = get_risk_level(risk_score)

    failed_logins = int((ip_events["event_type"] == "LOGIN_FAILED").sum())
    successful_logins = int((ip_events["event_type"] == "LOGIN_SUCCESS").sum())
    unique_users = int(ip_events["username"].nunique())

    first_row = st.columns(4)
    first_row[0].metric("Risk Score", risk_score)
    first_row[1].metric("Risk Level", risk_level)
    first_row[2].metric("Total Events", f"{len(ip_events):,}")
    first_row[3].metric("Unique Users Targeted", f"{unique_users:,}")

    second_row = st.columns(4)
    second_row[0].metric("Failed Logins", f"{failed_logins:,}")
    second_row[1].metric("Successful Logins", f"{successful_logins:,}")
    second_row[2].metric("First Seen", ip_events["timestamp"].min().strftime("%Y-%m-%d %H:%M"))
    second_row[3].metric("Last Seen", ip_events["timestamp"].max().strftime("%Y-%m-%d %H:%M"))

    triggered_types = (
        ", ".join(sorted_options(ip_alerts, "alert_type")) or "None"
    )
    techniques = (
        ", ".join(sorted_options(ip_alerts, "mitre_technique")) or "None"
    )
    st.markdown(f"**Triggered alert types:** {triggered_types}")
    st.markdown(f"**MITRE ATT&CK techniques:** {techniques}")

    st.subheader("Chronological Event Timeline")
    timeline = ip_events.sort_values("timestamp")
    figure = px.scatter(
        timeline,
        x="timestamp",
        y="event_type",
        color="event_type",
        hover_data=["username", "hostname", "country"],
    )
    figure.update_traces(marker={"size": 9})
    figure.update_layout(xaxis_title=None, yaxis_title=None, showlegend=True)
    st.plotly_chart(figure, width="stretch", theme="streamlit")

    event_columns = [
        column
        for column in (
            "timestamp",
            "event_type",
            "username",
            "hostname",
            "country",
        )
        if column in timeline
    ]
    st.dataframe(
        timeline.loc[:, event_columns],
        hide_index=True,
        width="stretch",
    )


def render_dashboard_content(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    filter_values: tuple[list[str], list[str], list[str], list[str], list[str]],
) -> None:
    """Render all existing dashboard sections for the current event slice."""
    filtered_alerts = apply_alert_filters(alerts, *filter_values)
    render_metrics(logs, alerts)
    st.divider()
    render_alert_table(filtered_alerts)
    render_alert_charts(filtered_alerts)
    render_activity_charts(logs)
    render_mitre_section(filtered_alerts)
    st.divider()
    render_investigation(logs, alerts)


@st.fragment(run_every=1.0)
def render_live_dashboard(
    full_logs: pd.DataFrame,
    events_per_second: int,
    filter_values: tuple[list[str], list[str], list[str], list[str], list[str]],
) -> None:
    """Refresh a progressively revealed event stream without a blocking loop."""
    processed = advance_live_progress(len(full_logs), events_per_second)
    active_logs = full_logs.iloc[:processed].copy()
    active_alerts = run_security_pipeline(active_logs)

    st.subheader("Live Monitoring Status")
    st.write(f"**Events Processed:** {processed:,} / {len(full_logs):,}")
    progress = processed / len(full_logs) if len(full_logs) else 0.0
    st.progress(progress, text=f"{progress:.1%} complete")
    if st.session_state.get("live_running", False):
        st.caption(f"Simulation running at {events_per_second} event(s) per second.")
    elif processed >= len(full_logs) and len(full_logs):
        st.success("Simulation complete.")
    else:
        st.caption("Simulation paused. Use Start to continue.")

    render_live_alert_feed(active_alerts)
    render_dashboard_content(active_logs, active_alerts, filter_values)


def main() -> None:
    """Render the complete SOC dashboard."""
    st.title("SOC Threat Detection Dashboard")
    st.caption(
        "Authentication monitoring, rule-based threat detection, and explainable risk scoring"
    )

    st.sidebar.header("Data Source")
    data_source = st.sidebar.radio(
        "Choose authentication data",
        ["Default Dataset", "Upload Your Own CSV"],
    )

    raw_upload: pd.DataFrame | None = None
    uploaded_filename = ""
    removed_rows = 0

    if data_source == "Default Dataset":
        try:
            logs = load_default_logs(str(DATA_PATH))
        except (FileNotFoundError, ValueError, pd.errors.EmptyDataError) as error:
            st.error(f"Unable to load the default security logs: {error}")
            st.stop()
        source_label = "Default Synthetic Dataset"
        file_signature = DATA_PATH.stat().st_mtime_ns if DATA_PATH.exists() else 0
        dataset_key = f"default:{file_signature}"
    else:
        uploaded_file = st.sidebar.file_uploader(
            "Upload authentication logs",
            type=["csv"],
            help="The uploaded file is analyzed in memory and does not overwrite the default dataset.",
        )
        if uploaded_file is None:
            st.info("Upload a CSV file from the Data Source section to begin analysis.")
            render_how_it_works()
            st.stop()

        uploaded_filename = uploaded_file.name
        st.sidebar.success(f"Selected: {uploaded_filename}")
        file_bytes = uploaded_file.getvalue()
        if not file_bytes:
            st.error("The uploaded CSV is empty. Select a file containing authentication events.")
            st.stop()

        try:
            raw_upload, logs = load_uploaded_logs(file_bytes)
        except pd.errors.EmptyDataError:
            st.error("The uploaded CSV is empty or contains no readable columns.")
            st.stop()
        except pd.errors.ParserError as error:
            st.error(f"The uploaded CSV could not be parsed: {error}")
            st.stop()
        except UnicodeDecodeError:
            st.error("The uploaded file is not a readable text CSV.")
            st.stop()
        except ValueError as error:
            st.error(f"Uploaded CSV validation failed. {error}")
            st.stop()

        if raw_upload.empty:
            st.error("The uploaded CSV has column headers but contains no event rows.")
            st.stop()
        if logs.empty:
            st.error(
                "No valid authentication events remain after cleaning. Check timestamps, "
                "missing values, and event types."
            )
            st.stop()

        removed_rows = len(raw_upload) - len(logs)
        source_label = f"Uploaded CSV — {uploaded_filename}"
        dataset_key = "upload:" + hashlib.sha256(file_bytes).hexdigest()

    if logs.empty:
        st.warning("The active dataset has no valid events to analyze.")
        st.stop()

    initialize_live_state(dataset_key)

    full_alerts = run_security_pipeline(logs)

    st.sidebar.divider()
    st.sidebar.header("Simulated Live Monitoring")
    st.sidebar.caption(
        "Replays the selected dataset over time to simulate events arriving in a SOC environment."
    )
    live_enabled = st.sidebar.toggle("Enable Live Simulation", value=False)
    speed_label = st.sidebar.selectbox(
        "Simulation speed",
        [
            "1 event per second",
            "5 events per second",
            "25 events per second",
            "100 events per second",
        ],
        disabled=not live_enabled,
    )
    speed_map = {
        "1 event per second": 1,
        "5 events per second": 5,
        "25 events per second": 25,
        "100 events per second": 100,
    }
    events_per_second = speed_map[speed_label]

    start_column, pause_column, reset_column = st.sidebar.columns(3)
    if start_column.button("Start", disabled=not live_enabled, width="stretch"):
        if st.session_state.live_processed >= len(logs):
            st.session_state.live_processed = 0
            st.session_state.live_seen_alerts = set()
        st.session_state.live_running = True
        st.session_state.live_last_tick = time.monotonic()
    if pause_column.button("Pause", disabled=not live_enabled, width="stretch"):
        st.session_state.live_running = False
    if reset_column.button("Reset", disabled=not live_enabled, width="stretch"):
        st.session_state.live_processed = 0
        st.session_state.live_running = False
        st.session_state.live_last_tick = time.monotonic()
        st.session_state.live_seen_alerts = set()

    # Update the source indicator after the mode toggle is known.
    render_source_indicator(source_label, live_enabled)
    if removed_rows > 0:
        st.warning(
            f"The parser safely removed {removed_rows:,} duplicate or malformed row(s)."
        )
    if raw_upload is not None:
        render_raw_preview(raw_upload, uploaded_filename)

    st.sidebar.divider()
    st.sidebar.header("Alert Filters")
    severity_options = sorted_options(full_alerts, "severity")
    risk_options = sorted_options(full_alerts, "risk_level")
    type_options = sorted_options(full_alerts, "alert_type")
    ip_options = sorted_options(full_alerts, "source_ip")
    username_options = sorted_options(full_alerts, "username")
    widget_suffix = hashlib.sha256(dataset_key.encode()).hexdigest()[:10]

    selected_severities = st.sidebar.multiselect(
        "Severity",
        severity_options,
        default=severity_options,
        key=f"severity_{widget_suffix}",
    )
    selected_risk_levels = st.sidebar.multiselect(
        "Risk level",
        risk_options,
        default=risk_options,
        key=f"risk_{widget_suffix}",
    )
    selected_types = st.sidebar.multiselect(
        "Alert type",
        type_options,
        default=type_options,
        key=f"type_{widget_suffix}",
    )
    selected_ips = st.sidebar.multiselect(
        "Source IP",
        ip_options,
        default=ip_options,
        key=f"ip_{widget_suffix}",
    )
    selected_usernames = st.sidebar.multiselect(
        "Username",
        username_options,
        default=username_options,
        key=f"username_{widget_suffix}",
    )
    filter_values = (
        selected_severities,
        selected_risk_levels,
        selected_types,
        selected_ips,
        selected_usernames,
    )

    if live_enabled:
        render_live_dashboard(logs, events_per_second, filter_values)
    else:
        render_dashboard_content(logs, full_alerts, filter_values)

    render_how_it_works()


if __name__ == "__main__":
    main()
