import copy

import pytest
from conftest import SAMPLE_METRICS

from generate_report import (
    _format_delta,
    _weekly_highlights,
    detect_security_signals,
    format_pr_status,
    format_related_issues,
    format_repo_stats,
    format_security_signals,
    generate_daily_report,
    generate_weekly_report,
)


@pytest.fixture
def metrics():
    return copy.deepcopy(SAMPLE_METRICS)


def test_format_pr_status_open(metrics):
    out = format_pr_status(metrics["pr"])
    assert "## PR Status" in out
    assert "#62099" in out
    assert "OPEN" in out
    assert "🟢" in out
    assert "👍 7" in out


def test_format_pr_status_merged(metrics):
    metrics["pr"]["state"] = "closed"
    metrics["pr"]["merged_at"] = "2026-06-25T00:00:00Z"
    out = format_pr_status(metrics["pr"])
    assert "🟣" in out
    assert "✅" in out


def test_format_pr_status_includes_recent_comments(metrics):
    out = format_pr_status(metrics["pr"])
    assert "Recent Comments" in out
    assert "reviewer" in out


def test_format_repo_stats(metrics):
    out = format_repo_stats(metrics["repo"])
    assert "anthropics/claude-code" in out
    assert "12,345" in out
    assert "TypeScript" in out
    assert "`security`" in out


def test_format_repo_stats_handles_null_language(metrics):
    metrics["repo"]["language"] = None
    out = format_repo_stats(metrics["repo"])
    assert "N/A" in out


def test_format_related_issues_counts(metrics):
    out = format_related_issues(metrics["related_issues"])
    assert "Found 1 related issues across 2 keywords" in out
    assert "#100" in out
    assert "Credential" in out


def test_format_related_issues_skips_empty_keyword(metrics):
    out = format_related_issues(metrics["related_issues"])
    assert "### Secrets" not in out


def test_generate_daily_report_sections(metrics):
    out = generate_daily_report(metrics)
    assert "Daily Report" in out
    assert "PR Status" in out
    assert "Repository Stats" in out
    assert "Related Issues" in out
    assert "Key Insights" in out
    assert "2026-06-25" in out


def test_generate_weekly_report_empty_history():
    assert generate_weekly_report([]) == "No metrics history available."


def test_generate_weekly_report_trend(metrics):
    start = copy.deepcopy(metrics)
    start["pr"]["comments_count"] = 8
    start["repo"]["stars"] = 12000
    end = metrics
    out = generate_weekly_report([start, end])
    assert "Weekly Rollup" in out
    assert "+4" in out  # comments 8 -> 12
    assert "+345" in out  # stars 12000 -> 12345


@pytest.mark.parametrize(
    "delta,expected",
    [(5, "+5"), (-3, "-3"), (0, "0")],
)
def test_format_delta(delta, expected):
    assert _format_delta(delta) == expected


def test_weekly_report_negative_star_delta_no_double_sign(metrics):
    start = copy.deepcopy(metrics)
    start["repo"]["stars"] = 12500  # ends lower at 12345
    out = generate_weekly_report([start, metrics])
    assert "+-" not in out
    assert "-155" in out
    assert "Declining Interest" in out


def test_weekly_highlights_data_driven(metrics):
    start = copy.deepcopy(metrics)
    start["repo"]["stars"] = 12000
    start["pr"]["comments_count"] = 10
    out = _weekly_highlights(start, metrics)
    assert "Growing Interest" in out
    assert "Active Discussion" in out
    assert "Open" in out


def test_weekly_highlights_stable_and_merged(metrics):
    start = copy.deepcopy(metrics)
    end = copy.deepcopy(metrics)
    end["pr"]["merged_at"] = "2026-06-25T00:00:00Z"
    end["pr"]["state"] = "closed"
    out = _weekly_highlights(start, end)
    assert "Merged" in out
    assert "Stable Interest" in out  # stars unchanged


def test_detect_security_signals_ranks_by_severity():
    metrics = {
        "related_issues": {
            "secret": [
                {"number": 1, "title": "Exposed secret in build logs", "state": "open",
                 "url": "u1", "comments": 2},
                {"number": 2, "title": "Add password reset flow", "state": "closed",
                 "url": "u2", "comments": 0},
            ],
            "supply": [
                {"number": 3, "title": "Supply chain risk in dependency", "state": "open",
                 "url": "u3", "comments": 9},
            ],
        }
    }
    signals = detect_security_signals(metrics)
    assert [s["number"] for s in signals] == [1, 3, 2]
    assert signals[0]["severity"] == "critical"
    assert signals[1]["severity"] == "high"
    assert signals[2]["severity"] == "medium"


def test_detect_security_signals_dedupes_to_highest_severity():
    metrics = {
        "related_issues": {
            "a": [{"number": 5, "title": "leak of data", "state": "open", "url": "u", "comments": 0}],
            "b": [{"number": 5, "title": "Leaked credential exposed", "state": "open", "url": "u", "comments": 0}],
        }
    }
    signals = detect_security_signals(metrics)
    assert len(signals) == 1
    assert signals[0]["severity"] == "critical"


def test_detect_security_signals_ignores_benign():
    metrics = {"related_issues": {"x": [
        {"number": 9, "title": "Improve docs formatting", "state": "open", "url": "u", "comments": 0},
    ]}}
    assert detect_security_signals(metrics) == []


def test_detect_security_signals_no_false_positive_on_rce_substring():
    metrics = {"related_issues": {"x": [
        {"number": 21, "title": "Add resource cleanup helper", "state": "open", "url": "u", "comments": 0},
        {"number": 22, "title": "Refactor source map loader", "state": "open", "url": "u", "comments": 0},
        {"number": 23, "title": "Enforce lint rules in commerce module", "state": "open", "url": "u", "comments": 0},
    ]}}
    assert detect_security_signals(metrics) == []


def test_detect_security_signals_still_matches_rce_as_word():
    metrics = {"related_issues": {"x": [
        {"number": 24, "title": "Possible RCE in template parser", "state": "open", "url": "u", "comments": 1},
    ]}}
    signals = detect_security_signals(metrics)
    assert len(signals) == 1
    assert signals[0]["severity"] == "critical"
    assert signals[0]["matched_term"] == "rce"


def test_detect_security_signals_stem_terms_still_match():
    metrics = {"related_issues": {"x": [
        {"number": 25, "title": "Token exfiltration via webhook", "state": "open", "url": "u", "comments": 0},
        {"number": 26, "title": "SQL injection vulnerability report", "state": "open", "url": "u", "comments": 0},
    ]}}
    by_number = {s["number"]: s for s in detect_security_signals(metrics)}
    assert by_number[25]["severity"] == "high"
    assert by_number[26]["severity"] == "medium"


def test_detect_security_signals_matches_hyphenated_multiword():
    metrics = {"related_issues": {"x": [
        {"number": 27, "title": "Supply-chain attack via malicious npm package", "state": "open", "url": "u", "comments": 0},
        {"number": 28, "title": "Remote-code-execution in template parser", "state": "open", "url": "u", "comments": 0},
    ]}}
    by_number = {s["number"]: s for s in detect_security_signals(metrics)}
    assert by_number[27]["severity"] == "high"
    assert by_number[27]["matched_term"] == "supply chain"
    assert by_number[28]["severity"] == "critical"
    assert by_number[28]["matched_term"] == "remote code execution"


def test_detect_security_signals_matches_wrapped_multiword_in_body():
    metrics = {"related_issues": {"x": [
        {"number": 29, "title": "Investigate token handling", "state": "open", "url": "u", "comments": 0,
         "body": "The exposed\nsecret was committed to the public repo."},
    ]}}
    signals = detect_security_signals(metrics)
    assert len(signals) == 1
    assert signals[0]["severity"] == "critical"
    assert signals[0]["matched_term"] == "exposed secret"
    assert signals[0]["matched_in"] == "body"


def test_detect_security_signals_matches_body_when_title_clean():
    metrics = {"related_issues": {"x": [
        {"number": 11, "title": "Improve logging output", "state": "open", "url": "u",
         "comments": 3, "body": "We accidentally print a leaked credential to stdout."},
    ]}}
    signals = detect_security_signals(metrics)
    assert len(signals) == 1
    assert signals[0]["severity"] == "critical"
    assert signals[0]["matched_in"] == "body"
    assert signals[0]["matched_term"] == "leaked credential"


def test_detect_security_signals_title_preferred_over_body_on_tie():
    metrics = {"related_issues": {"x": [
        {"number": 12, "title": "password handling cleanup", "state": "open", "url": "u",
         "comments": 0, "body": "also touches injection paths"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["matched_in"] == "title"
    assert signals[0]["severity"] == "medium"


def test_detect_security_signals_body_outranks_lower_title():
    metrics = {"related_issues": {"x": [
        {"number": 13, "title": "minor leak in cache", "state": "open", "url": "u",
         "comments": 0, "body": "Turns out this is a remote code execution bug."},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["severity"] == "critical"
    assert signals[0]["matched_in"] == "body"


def test_detect_security_signals_missing_body_ok():
    metrics = {"related_issues": {"x": [
        {"number": 14, "title": "Exposed secret in CI", "state": "open", "url": "u", "comments": 1},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["matched_in"] == "title"


def test_format_security_signals_renders_matched_in():
    signals = [
        {"number": 1, "title": "Logging cleanup", "url": "u", "state": "open",
         "comments": 2, "severity": "critical", "matched_term": "leaked credential",
         "matched_in": "body"},
    ]
    out = format_security_signals(signals)
    assert "matched `leaked credential` in body" in out


def test_format_security_signals_empty():
    out = format_security_signals([])
    assert "No elevated security signals" in out
    assert "## 🔐 Security Signals" in out


def test_format_security_signals_renders_counts():
    signals = [
        {"number": 1, "title": "Exposed secret", "url": "u", "state": "open",
         "comments": 2, "severity": "critical", "matched_term": "exposed secret"},
    ]
    out = format_security_signals(signals)
    assert "1 critical" in out
    assert "CRITICAL" in out
    assert "matched `exposed secret`" in out


def test_daily_report_includes_security_signals(metrics):
    metrics["related_issues"]["secrets"] = [
        {"number": 100, "title": "Secrets leak in logs", "state": "open",
         "url": "https://x/issues/100", "comments": 5, "created_at": "2026-06-01T00:00:00Z"},
    ]
    out = generate_daily_report(metrics)
    assert "## 🔐 Security Signals" in out
    assert "Security Signals:" in out
