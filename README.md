# Security Log Analysis

A small Python project that analyzes Apache/Nginx-style web access logs and highlights request patterns that may deserve security investigation.

The goal of this project is to practise **log parsing, detection logic, Python scripting and security analysis** using a transparent implementation built only with the Python standard library.

> The included log data is synthetic and uses documentation-only IP address ranges. No real user or production data is included.

## What the analyzer detects

The script currently looks for four simple indicators:

- **High request volume** — an IP generating more requests than a configurable threshold.
- **Error bursts** — repeated HTTP `4xx` or `5xx` responses from the same source.
- **Sensitive-path probing** — requests for paths such as `/admin`, `/.env`, `/.git`, `/wp-admin` and `/phpmyadmin`.
- **Highly regular request intervals** — repeated requests occurring at almost identical intervals, which can be an indicator of scripted or automated activity.

These detections are intentionally treated as **investigative signals rather than proof of malicious activity**. Context from authentication logs, application behaviour and other telemetry would be needed before reaching a security conclusion.

## Project structure

```text
security-log-analysis/
├── log_analyzer.py
├── sample_logs/
│   └── web_access.log
├── reports/
│   └── example_report.txt
├── tests/
│   └── test_log_analyzer.py
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10+
- No third-party Python packages

## Run the analyzer

Clone the repository and run:

```bash
python log_analyzer.py sample_logs/web_access.log
```

To save the output to a file:

```bash
python log_analyzer.py sample_logs/web_access.log -o reports/report.txt
```

Thresholds can also be changed:

```bash
python log_analyzer.py sample_logs/web_access.log \
  --high-volume-threshold 15 \
  --error-threshold 5
```

## Example findings

Using the included synthetic log, the analyzer identifies:

- a source sending a high number of requests;
- a client probing several commonly sensitive paths and receiving repeated `403/404` responses;
- request sequences occurring at consistent intervals, indicating possible automation.

An example generated result is available in [`reports/example_report.txt`](reports/example_report.txt).

## Run the tests

The project uses Python's built-in `unittest` framework:

```bash
python -m unittest discover -s tests -v
```

The tests cover:

- valid log-line parsing;
- malformed input handling;
- sensitive-path and error-burst detection;
- regular-interval automation detection.

## How it works

1. Each access-log line is parsed into a structured `LogEntry`.
2. Requests are grouped and counted by source IP.
3. HTTP error responses and sensitive paths are identified.
4. Request timestamps are compared to detect unusually regular timing patterns.
5. The findings are converted into a readable security report.

## Example security interpretation

A request to `/admin` or `/.env` is not automatically an attack. Likewise, requests every 10 seconds may be produced by a legitimate monitoring tool. The useful signal appears when multiple observations are correlated — for example, regular automated timing combined with sensitive-path probing and repeated error responses.

This distinction between **detection** and **interpretation** is an important part of practical security analysis.

## Skills demonstrated

- Python
- Log parsing
- Data aggregation
- Basic detection engineering
- Web / HTTP fundamentals
- Security analysis
- Unit testing
- Git & GitHub

## Possible next improvements

- Parse user-agent and referrer fields.
- Add configurable suspicious-path rules.
- Detect failed-login bursts.
- Add sliding-window request-rate detection.
- Export findings as JSON or CSV.
- Add severity levels and confidence scores.
- Add GitHub Actions for automated testing.

## Author

**Petros Chatzistefanou**  
BSc Applied Informatics — Information Systems, University of Macedonia  
[LinkedIn](https://www.linkedin.com/in/petros-chatzistefanou/)
