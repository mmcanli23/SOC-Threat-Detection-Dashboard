"""Load, validate, and normalize authentication security logs."""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import IO

import pandas as pd


REQUIRED_COLUMNS = (
    "timestamp",
    "source_ip",
    "username",
    "hostname",
    "event_type",
    "country",
)

VALID_EVENT_TYPES = {
    "LOGIN_SUCCESS",
    "LOGIN_FAILED",
    "ACCOUNT_LOCKED",
    "PASSWORD_RESET",
}


def load_security_logs(file_path: str | Path | IO[str] | IO[bytes]) -> pd.DataFrame:
    """Load a security-log CSV and return clean chronological events.

    Rows with missing required values, invalid timestamps, or unsupported event
    types are safely excluded. Missing required columns raise a clear error.
    """
    if hasattr(file_path, "read"):
        source = file_path
        if hasattr(source, "seek"):
            source.seek(0)
    else:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Security log file not found: {path}")
        source = path

    # Preserve valid values such as country code "NA" (Namibia).
    df = pd.read_csv(source, keep_default_na=False, na_values=[""])

    missing_columns = [column for column in REQUIRED_COLUMNS if column not in df]
    if missing_columns:
        raise ValueError(
            "Missing required columns: " + ", ".join(missing_columns)
        )

    df = df.loc[:, list(REQUIRED_COLUMNS)].copy()
    df["timestamp"] = pd.to_datetime(
        df["timestamp"], format="mixed", errors="coerce", utc=True
    )

    text_columns = [column for column in REQUIRED_COLUMNS if column != "timestamp"]
    for column in text_columns:
        df[column] = df[column].astype("string").str.strip()
        df[column] = df[column].replace("", pd.NA)

    df = df.drop_duplicates()
    df = df.dropna(subset=list(REQUIRED_COLUMNS))

    valid_mask = df["event_type"].isin(VALID_EVENT_TYPES)
    if not valid_mask.all():
        invalid_types = sorted(df.loc[~valid_mask, "event_type"].unique().tolist())
        warnings.warn(
            "Removed rows with invalid event types: " + ", ".join(invalid_types),
            UserWarning,
            stacklevel=2,
        )
        df = df.loc[valid_mask]

    return df.sort_values("timestamp").reset_index(drop=True)


if __name__ == "__main__":
    logs_path = Path(__file__).resolve().parent / "data" / "security_logs.csv"
    logs = load_security_logs(logs_path)
    print(f"Total events: {len(logs):,}")
    print(logs.head())
    print(list(logs.columns))
    print(f"Earliest timestamp: {logs['timestamp'].min()}")
    print(f"Latest timestamp: {logs['timestamp'].max()}")
    print(logs["event_type"].value_counts())
