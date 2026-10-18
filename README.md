# SOC Threat Detection Dashboard

## Overview

The SOC Threat Detection Dashboard is a Python-based, SOC-style security
monitoring project that analyzes authentication logs and identifies suspicious
login behavior. It turns raw events into prioritized alerts and presents them
through an interactive dashboard designed around a basic analyst workflow.

The project uses synthetic authentication data to safely simulate normal user
activity and several attack scenarios. It does not use real corporate data and
is intended as an educational cybersecurity portfolio project rather than a
production security product.

## Key Features

- Brute-force detection
- Password-spraying detection
- Detection of repeated failed logins followed by a successful login
- Explainable risk scoring from 0–100
- LOW, MEDIUM, HIGH, and CRITICAL risk classification
- MITRE ATT&CK technique mapping
- Interactive Streamlit SOC dashboard
- Upload Your Own CSV workflow
- In-memory CSV analysis without overwriting the default dataset
- Uploaded dataset validation and preview
- Simulated Live Monitoring
- Adjustable event playback speed
- Start, Pause, and Reset playback controls
- Live alert feed with high-priority alert emphasis
- Clear source-data and operating-mode indicators
- Source IP investigation workflow
- Username targeting analysis
- Alert filtering by severity, risk, type, IP, and username
- Automated detection tests with pytest

## Project Architecture

```text
Default Synthetic Dataset          User Uploaded CSV
generator.py                       (analyzed in memory)
        ↓                                  ↓
data/security_logs.csv                     │
        └─────────────── OR ───────────────┘
                            ↓
                        parser.py
                            ↓
                       detector.py
                            ↓
                    risk_scoring.py
                            ↓
                          app.py
                            ↓
          SOC Dashboard / Simulated Live Monitoring
```

Uploaded CSV files are analyzed in memory and never overwrite
`data/security_logs.csv`. Simulated Live Monitoring replays whichever dataset
is selected by progressively revealing its existing events and rerunning the
detection pipeline. It is not a connection to a production SIEM, a live
corporate network, or a real-time corporate data source.

## Detection Rules

### Brute Force

Triggers when the same source IP generates at least five failed authentication
attempts against the same username within two minutes.

**MITRE ATT&CK:** T1110 — Brute Force

### Password Spraying

Triggers when the same source IP generates failed authentication attempts
against at least five unique usernames within five minutes.

**MITRE ATT&CK:** T1110.003 — Password Spraying

### Suspicious Successful Authentication

Triggers when at least five failed logins are followed by a successful login
from the same source IP against the same user account within ten minutes.

**Severity:** CRITICAL  
**MITRE ATT&CK:** T1110 — Brute Force

## Risk Scoring

Each alert receives a rule-based score from 0–100. The score begins with a base
value for the alert type and can increase based on factors such as failed-login
volume, number of usernames targeted, successful authentication after repeated
failures, activity frequency, and detection severity.

| Score | Risk level |
|---:|:---|
| 0–39 | LOW |
| 40–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

The scoring model is intentionally explainable: each increase is tied to a
visible rule rather than an opaque model.

## Technologies Used

- Python
- Pandas
- Streamlit
- Plotly
- Pytest
- Faker

## Project Structure

```text
soc-threat-detection-dashboard/
├── app.py
├── detector.py
├── generator.py
├── parser.py
├── risk_scoring.py
├── requirements.txt
├── pytest.ini
├── README.md
├── .gitignore
├── data/
│   └── security_logs.csv
├── tests/
│   └── test_detector.py
└── screenshots/
```

- `app.py` — Builds the dashboard, upload workflow, simulated playback, and investigation interface.
- `detector.py` — Applies the authentication threat-detection rules.
- `generator.py` — Creates synthetic normal and malicious authentication events.
- `parser.py` — Validates, cleans, normalizes, and orders the log data.
- `risk_scoring.py` — Assigns explainable risk scores and risk levels to alerts.
- `requirements.txt` — Lists the Python dependencies.
- `pytest.ini` — Ensures tests can import project modules from the project root.
- `data/` — Stores the generated authentication dataset.
- `tests/` — Contains automated tests for the detection rules.
- `screenshots/` — Stores portfolio screenshots of the dashboard.

## How to Run

From the project directory:

1. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Generate the synthetic authentication data:

   ```bash
   python3 generator.py
   ```

4. Run the detections from the terminal:

   ```bash
   python3 detector.py
   ```

5. Run the automated tests:

   ```bash
   pytest
   ```

6. Launch the dashboard:

   ```bash
   streamlit run app.py
   ```

Streamlit will normally make the dashboard available at
`http://localhost:8501`.

### Analyze an Uploaded CSV

In the dashboard sidebar, select **Upload Your Own CSV** and choose a `.csv`
file. Uploaded files must contain these columns:

```text
timestamp, source_ip, username, hostname, event_type, country
```

The app validates and cleans the upload in memory, displays a dataset preview,
and runs the same detection and scoring pipeline used for the default dataset.
The uploaded file is not saved over the sample dataset.

### Use Simulated Live Monitoring

Enable **Simulated Live Monitoring** in the sidebar, select a playback speed,
and use **Start**, **Pause**, or **Reset**. The feature progressively replays
the selected default or uploaded dataset, updates progress, reruns detections,
and displays newly surfaced alerts in the live alert feed. This is simulated
event playback, not production monitoring.

## Screenshots

Add screenshots to the `screenshots/` directory using the filenames below.

![SOC Dashboard](screenshots/dashboard.png)

![IP Investigation](screenshots/investigation.png)

## What I Learned

This project helped me understand how authentication logs can be transformed
into useful security alerts. I practiced building time-window-based detection
rules, prioritizing alerts with explainable risk scores, and connecting results
to MITRE ATT&CK techniques. I also learned how small threshold changes can
affect false positives and false negatives, and why detection logic needs
repeatable tests. Building the dashboard gave me a better understanding of how
a SOC analyst moves from a high-level alert summary into a focused source-IP
investigation.

## Future Improvements

- Parse Windows Event Logs and common identity-provider formats
- Add JSON log-format support
- Integrate with a SIEM or log-ingestion pipeline
- Add Sigma rule support
- Enrich source IPs with GeoIP information
- Add IP reputation and threat-intelligence checks
- Evaluate the rules against public security datasets
- Expand coverage to additional MITRE ATT&CK techniques
- Add configurable thresholds and detection windows
- Add authenticated ingestion of real events from supported security sources
