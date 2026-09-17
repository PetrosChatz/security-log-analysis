#!/usr/bin/env python3
"""Simple web access log analyzer for security-focused portfolio use.

The script parses Apache/Nginx-style combined access logs and highlights:
- high request volume from a single IP
- repeated client/server error responses
- requests to commonly probed sensitive paths
- highly regular request intervals that may indicate automation

It intentionally uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Iterable


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

SUSPICIOUS_PATH_KEYWORDS = (
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/.git",
    "/server-status",
)


@dataclass(frozen=True)
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int


def parse_log_line(line: str) -> LogEntry | None:
    """Parse one access-log line.

    Returns None for malformed or unsupported lines instead of crashing the
    whole analysis.
    """
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    try:
        timestamp = datetime.strptime(match.group("timestamp"), TIMESTAMP_FORMAT)
        status = int(match.group("status"))
    except (ValueError, TypeError):
        return None

    return LogEntry(
        ip=match.group("ip"),
        timestamp=timestamp,
        method=match.group("method"),
        path=match.group("path"),
        status=status,
    )


def load_entries(log_path: Path) -> tuple[list[LogEntry], int]:
    """Load valid entries and return them with the malformed-line count."""
    entries: list[LogEntry] = []
    malformed = 0

    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            entry = parse_log_line(line)
            if entry is None:
                malformed += 1
            else:
                entries.append(entry)

    return entries, malformed


def _regular_interval_score(timestamps: Iterable[datetime]) -> tuple[bool, float | None]:
    """Detect near-identical request intervals.

    Five or more requests are required. If every interval differs from the
    average interval by at most one second, the sequence is considered highly
    regular and therefore worth reviewing as possible automation.
    """
    ordered = sorted(timestamps)
    if len(ordered) < 5:
        return False, None

    intervals = [
        (current - previous).total_seconds()
        for previous, current in zip(ordered, ordered[1:])
    ]
    if not intervals:
        return False, None

    average = mean(intervals)
    if average <= 0:
        return False, average

    regular = all(abs(interval - average) <= 1.0 for interval in intervals)
    return regular, average


def analyze_entries(
    entries: list[LogEntry],
    high_volume_threshold: int = 10,
    error_threshold: int = 4,
) -> dict:
    """Analyze parsed log entries and return structured findings."""
    requests_by_ip = Counter(entry.ip for entry in entries)
    status_counts = Counter(entry.status for entry in entries)

    errors_by_ip: Counter[str] = Counter()
    suspicious_paths: list[LogEntry] = []
    timestamps_by_ip: dict[str, list[datetime]] = defaultdict(list)

    for entry in entries:
        timestamps_by_ip[entry.ip].append(entry.timestamp)

        if entry.status >= 400:
            errors_by_ip[entry.ip] += 1

        normalized_path = entry.path.lower()
        if any(keyword in normalized_path for keyword in SUSPICIOUS_PATH_KEYWORDS):
            suspicious_paths.append(entry)

    high_volume_ips = {
        ip: count
        for ip, count in requests_by_ip.items()
        if count >= high_volume_threshold
    }

    high_error_ips = {
        ip: count for ip, count in errors_by_ip.items() if count >= error_threshold
    }

    automated_ips: dict[str, float] = {}
    for ip, timestamps in timestamps_by_ip.items():
        regular, average_interval = _regular_interval_score(timestamps)
        if regular and average_interval is not None:
            automated_ips[ip] = average_interval

    return {
        "total_requests": len(entries),
        "unique_ips": len(requests_by_ip),
        "requests_by_ip": requests_by_ip,
        "status_counts": status_counts,
        "high_volume_ips": high_volume_ips,
        "high_error_ips": high_error_ips,
        "suspicious_paths": suspicious_paths,
        "automated_ips": automated_ips,
    }


def build_report(analysis: dict, malformed_lines: int = 0) -> str:
    """Create a human-readable security summary."""
    lines = [
        "SECURITY LOG ANALYSIS REPORT",
        "=" * 28,
        f"Total valid requests: {analysis['total_requests']}",
        f"Unique source IPs: {analysis['unique_ips']}",
        f"Malformed/skipped lines: {malformed_lines}",
        "",
        "HTTP STATUS SUMMARY",
        "-------------------",
    ]

    for status, count in sorted(analysis["status_counts"].items()):
        lines.append(f"{status}: {count}")

    lines.extend(["", "FINDINGS", "--------"])

    if analysis["high_volume_ips"]:
        for ip, count in sorted(analysis["high_volume_ips"].items()):
            lines.append(f"[HIGH VOLUME] {ip}: {count} requests")
    else:
        lines.append("[HIGH VOLUME] No IP exceeded the configured threshold")

    if analysis["high_error_ips"]:
        for ip, count in sorted(analysis["high_error_ips"].items()):
            lines.append(f"[ERROR BURST] {ip}: {count} HTTP 4xx/5xx responses")
    else:
        lines.append("[ERROR BURST] No IP exceeded the configured threshold")

    if analysis["automated_ips"]:
        for ip, interval in sorted(analysis["automated_ips"].items()):
            lines.append(
                f"[POSSIBLE AUTOMATION] {ip}: requests at ~{interval:.1f}s intervals"
            )
    else:
        lines.append("[POSSIBLE AUTOMATION] No highly regular request sequence detected")

    if analysis["suspicious_paths"]:
        lines.append("[SENSITIVE PATHS] Requests worth reviewing:")
        for entry in analysis["suspicious_paths"]:
            lines.append(
                f"  - {entry.ip} {entry.method} {entry.path} -> {entry.status}"
            )
    else:
        lines.append("[SENSITIVE PATHS] No common sensitive-path probes detected")

    lines.extend(
        [
            "",
            "INTERPRETATION",
            "--------------",
            "These findings are indicators for investigation, not proof of compromise.",
            "They should be correlated with authentication logs, application context,",
            "asset ownership and other telemetry before taking action.",
        ]
    )

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze web access logs for suspicious request patterns."
    )
    parser.add_argument("log_file", type=Path, help="Path to the access log file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional path to save the generated report",
    )
    parser.add_argument(
        "--high-volume-threshold",
        type=int,
        default=10,
        help="Requests from one IP required to flag high volume (default: 10)",
    )
    parser.add_argument(
        "--error-threshold",
        type=int,
        default=4,
        help="4xx/5xx responses from one IP required to flag an error burst (default: 4)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.log_file.exists():
        raise SystemExit(f"Log file not found: {args.log_file}")

    entries, malformed = load_entries(args.log_file)
    analysis = analyze_entries(
        entries,
        high_volume_threshold=args.high_volume_threshold,
        error_threshold=args.error_threshold,
    )
    report = build_report(analysis, malformed)

    print(report)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n", encoding="utf-8")
        print(f"\nReport saved to: {args.output}")


if __name__ == "__main__":
    main()
