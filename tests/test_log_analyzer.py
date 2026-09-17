import unittest
from datetime import datetime, timedelta, timezone

from log_analyzer import LogEntry, analyze_entries, parse_log_line


class ParseLogLineTests(unittest.TestCase):
    def test_parses_valid_combined_log_line(self):
        line = (
            '203.0.113.10 - - [17/Sep/2026:09:15:30 +0000] '
            '"GET /admin HTTP/1.1" 403 220 "-" "curl/8.0"'
        )

        entry = parse_log_line(line)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "203.0.113.10")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/admin")
        self.assertEqual(entry.status, 403)

    def test_returns_none_for_malformed_line(self):
        self.assertIsNone(parse_log_line("this is not a valid access log line"))


class AnalysisTests(unittest.TestCase):
    def test_detects_sensitive_paths_and_error_burst(self):
        base = datetime(2026, 9, 17, 9, 0, tzinfo=timezone.utc)
        entries = [
            LogEntry("198.51.100.5", base + timedelta(seconds=i * 2), "GET", path, 404)
            for i, path in enumerate(
                ["/admin", "/.env", "/.git/config", "/wp-admin"]
            )
        ]

        result = analyze_entries(entries, high_volume_threshold=10, error_threshold=4)

        self.assertEqual(result["high_error_ips"]["198.51.100.5"], 4)
        self.assertEqual(len(result["suspicious_paths"]), 4)

    def test_detects_regular_request_intervals_as_possible_automation(self):
        base = datetime(2026, 9, 17, 9, 0, tzinfo=timezone.utc)
        entries = [
            LogEntry(
                "203.0.113.45",
                base + timedelta(seconds=i * 10),
                "GET",
                "/api/status",
                200,
            )
            for i in range(6)
        ]

        result = analyze_entries(entries)

        self.assertIn("203.0.113.45", result["automated_ips"])
        self.assertEqual(result["automated_ips"]["203.0.113.45"], 10.0)


if __name__ == "__main__":
    unittest.main()
