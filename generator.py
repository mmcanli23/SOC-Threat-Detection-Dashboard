"""Generate synthetic authentication events for the SOC dashboard."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
from faker import Faker


TOTAL_EVENTS = 10_000
NORMAL_EVENTS = 9_000
OUTPUT_PATH = Path(__file__).resolve().parent / "data" / "security_logs.csv"
SEED = 42

EVENT_TYPES = (
    "LOGIN_SUCCESS",
    "LOGIN_FAILED",
    "ACCOUNT_LOCKED",
    "PASSWORD_RESET",
)


def country_code(fake: Faker) -> str:
    """Return a non-empty two-letter country code."""
    code = fake.country_code(representation="alpha-2")
    # Pandas treats the valid Namibia code "NA" as a missing-value marker.
    while not code or code == "NA":
        code = fake.country_code(representation="alpha-2")
    return code


def build_identity_pools(fake: Faker) -> tuple[list[str], list[str]]:
    """Create reusable users and hosts so repeated behavior can be detected."""
    usernames = [f"{fake.user_name()}_{index:03d}" for index in range(500)]
    hostnames = [f"workstation-{index:03d}" for index in range(1, 201)]
    return usernames, hostnames


def make_event(
    timestamp: datetime,
    source_ip: str,
    username: str,
    hostname: str,
    event_type: str,
    country: str,
) -> dict[str, object]:
    """Return one authentication event in the dataset's standard schema."""
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "username": username,
        "hostname": hostname,
        "event_type": event_type,
        "country": country,
    }


def generate_normal_events(
    fake: Faker,
    rng: random.Random,
    usernames: list[str],
    hostnames: list[str],
    count: int,
    start: datetime,
    end: datetime,
) -> list[dict[str, object]]:
    """Generate mostly successful, geographically varied user activity."""
    events = []
    event_weights = (91, 6, 1, 2)
    time_span_seconds = int((end - start).total_seconds())

    for _ in range(count):
        timestamp = start + timedelta(seconds=rng.randint(0, time_span_seconds))
        events.append(
            make_event(
                timestamp=timestamp,
                source_ip=fake.ipv4_public(),
                username=rng.choice(usernames),
                hostname=rng.choice(hostnames),
                event_type=rng.choices(EVENT_TYPES, weights=event_weights, k=1)[0],
                country=country_code(fake),
            )
        )

    return events


def generate_brute_force_attack(
    fake: Faker,
    rng: random.Random,
    usernames: list[str],
    hostnames: list[str],
    start: datetime,
    count: int = 250,
) -> list[dict[str, object]]:
    """Create rapid failures from one IP against one account."""
    source_ip = fake.ipv4_public()
    username = rng.choice(usernames)
    hostname = rng.choice(hostnames)
    country = country_code(fake)

    return [
        make_event(
            start + timedelta(seconds=index * 2),
            source_ip,
            username,
            hostname,
            "ACCOUNT_LOCKED" if index == count - 1 else "LOGIN_FAILED",
            country,
        )
        for index in range(count)
    ]


def generate_password_spray(
    fake: Faker,
    rng: random.Random,
    usernames: list[str],
    hostnames: list[str],
    start: datetime,
    count: int = 200,
) -> list[dict[str, object]]:
    """Create failed attempts from one IP across many accounts."""
    source_ip = fake.ipv4_public()
    country = country_code(fake)
    targets = rng.sample(usernames, count)

    return [
        make_event(
            start + timedelta(seconds=index * 8),
            source_ip,
            username,
            rng.choice(hostnames),
            "LOGIN_FAILED",
            country,
        )
        for index, username in enumerate(targets)
    ]


def generate_failed_then_successful_logins(
    fake: Faker,
    rng: random.Random,
    usernames: list[str],
    hostnames: list[str],
    start: datetime,
    count: int = 150,
) -> list[dict[str, object]]:
    """Create groups of five failures followed by a successful login."""
    events = []
    sequence_length = 6

    for sequence in range(count // sequence_length):
        source_ip = fake.ipv4_public()
        username = rng.choice(usernames)
        hostname = rng.choice(hostnames)
        country = country_code(fake)
        sequence_start = start + timedelta(minutes=sequence * 8)

        for attempt in range(sequence_length):
            events.append(
                make_event(
                    sequence_start + timedelta(seconds=attempt * 12),
                    source_ip,
                    username,
                    hostname,
                    "LOGIN_SUCCESS" if attempt == sequence_length - 1 else "LOGIN_FAILED",
                    country,
                )
            )

    return events


def generate_many_account_targeting(
    fake: Faker,
    rng: random.Random,
    usernames: list[str],
    hostnames: list[str],
    start: datetime,
    count: int = 200,
) -> list[dict[str, object]]:
    """Create one-IP activity targeting a broad set of user accounts."""
    source_ip = fake.ipv4_public()
    country = country_code(fake)
    targets = rng.sample(usernames, count)

    return [
        make_event(
            start + timedelta(seconds=index * 15),
            source_ip,
            username,
            rng.choice(hostnames),
            rng.choices(("LOGIN_FAILED", "LOGIN_SUCCESS"), weights=(9, 1), k=1)[0],
            country,
        )
        for index, username in enumerate(targets)
    ]


def generate_high_frequency_activity(
    fake: Faker,
    rng: random.Random,
    usernames: list[str],
    hostnames: list[str],
    start: datetime,
    count: int = 200,
) -> list[dict[str, object]]:
    """Create an unusually large burst of logins within a few minutes."""
    source_ip = fake.ipv4_public()
    username = rng.choice(usernames)
    hostname = rng.choice(hostnames)
    country = country_code(fake)

    return [
        make_event(
            start + timedelta(milliseconds=index * 900),
            source_ip,
            username,
            hostname,
            rng.choices(("LOGIN_SUCCESS", "LOGIN_FAILED"), weights=(7, 3), k=1)[0],
            country,
        )
        for index in range(count)
    ]


def generate_security_logs(total_events: int = TOTAL_EVENTS) -> pd.DataFrame:
    """Build normal activity plus all five injected attack patterns."""
    if total_events < 1_000:
        raise ValueError("total_events must be at least 1,000")

    fake = Faker()
    fake.seed_instance(SEED)
    rng = random.Random(SEED)
    usernames, hostnames = build_identity_pools(fake)

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=30)
    attack_start = end - timedelta(days=1)
    normal_count = total_events - 1_000

    events = generate_normal_events(
        fake, rng, usernames, hostnames, normal_count, start, end
    )
    events.extend(
        generate_brute_force_attack(
            fake, rng, usernames, hostnames, attack_start
        )
    )
    events.extend(
        generate_password_spray(
            fake, rng, usernames, hostnames, attack_start + timedelta(hours=2)
        )
    )
    events.extend(
        generate_failed_then_successful_logins(
            fake, rng, usernames, hostnames, attack_start + timedelta(hours=4)
        )
    )
    events.extend(
        generate_many_account_targeting(
            fake, rng, usernames, hostnames, attack_start + timedelta(hours=8)
        )
    )
    events.extend(
        generate_high_frequency_activity(
            fake, rng, usernames, hostnames, attack_start + timedelta(hours=12)
        )
    )

    dataframe = pd.DataFrame(events)
    dataframe = dataframe.sample(frac=1, random_state=SEED)
    return dataframe.sort_values("timestamp").reset_index(drop=True)


def save_security_logs(dataframe: pd.DataFrame, output_path: Path = OUTPUT_PATH) -> None:
    """Create the data directory if needed and write events to CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    dataframe.to_csv(output_path, index=False)


def main() -> None:
    """Generate the default dataset and report where it was saved."""
    dataframe = generate_security_logs()
    save_security_logs(dataframe)
    print(f"Generated {len(dataframe):,} events at {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
