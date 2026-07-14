import copy

import pytest
from conftest import SAMPLE_METRICS

from generate_report import (
    _format_delta,
    _weekly_highlights,
    detect_security_signals,
    extract_cve_ids,
    extract_ghsa_ids,
    extract_cwe_ids,
    extract_mal_ids,
    extract_pysec_ids,
    extract_rustsec_ids,
    extract_go_ids,
    format_pr_status,
    format_related_issues,
    format_repo_stats,
    format_security_signals,
    format_signal_insight,
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


def test_detect_security_signals_open_ranks_before_closed_within_severity():
    metrics = {
        "related_issues": {
            "secret": [
                {"number": 1, "title": "Exposed secret in old logs", "state": "closed",
                 "url": "u1", "comments": 9},
                {"number": 2, "title": "Exposed secret in build output", "state": "open",
                 "url": "u2", "comments": 0},
            ],
        }
    }
    signals = detect_security_signals(metrics)
    assert [s["number"] for s in signals] == [2, 1]
    assert all(s["severity"] == "critical" for s in signals)


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


def test_detect_security_signals_matches_supply_chain_attack_terms():
    metrics = {"related_issues": {"x": [
        {"number": 40, "title": "Backdoor found in model checkpoint", "state": "open", "url": "u", "comments": 0},
        {"number": 41, "title": "Malicious package published to PyPI", "state": "open", "url": "u", "comments": 0},
        {"number": 42, "title": "Typosquatting attack on popular npm library", "state": "open", "url": "u", "comments": 0},
        {"number": 43, "title": "Dependency confusion in internal registry", "state": "open", "url": "u", "comments": 0},
        {"number": 44, "title": "Data poisoning of the fine-tuning set", "state": "open", "url": "u", "comments": 0},
    ]}}
    by_number = {s["number"]: s for s in detect_security_signals(metrics)}
    assert by_number[40]["severity"] == "critical"
    assert by_number[40]["matched_term"] == "backdoor"
    assert by_number[41]["severity"] == "critical"
    assert by_number[42]["severity"] == "high"
    assert by_number[42]["matched_term"] == "typosquat"
    assert by_number[43]["severity"] == "high"
    assert by_number[44]["severity"] == "high"


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


def test_detect_security_signals_matches_bare_security_label():
    metrics = {"related_issues": {"x": [
        {"number": 30, "title": "Investigate flaky checkout flow", "state": "open",
         "url": "u", "comments": 2, "labels": ["security", "needs-triage"]},
    ]}}
    signals = detect_security_signals(metrics)
    assert len(signals) == 1
    assert signals[0]["severity"] == "high"
    assert signals[0]["matched_in"] == "label"
    assert signals[0]["matched_term"] == "security"


def test_detect_security_signals_label_preferred_over_body_on_tie():
    metrics = {"related_issues": {"x": [
        {"number": 31, "title": "Refactor config loader", "state": "open", "url": "u",
         "comments": 0, "labels": ["cve"], "body": "May relate to a credential path"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["severity"] == "high"
    assert signals[0]["matched_in"] == "label"


def test_detect_security_signals_hyphenated_label_matches_keyword_tier():
    metrics = {"related_issues": {"x": [
        {"number": 32, "title": "Dependency bump", "state": "open", "url": "u",
         "comments": 0, "labels": ["supply-chain"]},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["severity"] == "high"
    assert signals[0]["matched_term"] == "supply chain"
    assert signals[0]["matched_in"] == "label"


def test_detect_security_signals_benign_labels_ignored():
    metrics = {"related_issues": {"x": [
        {"number": 33, "title": "Update docs", "state": "open", "url": "u",
         "comments": 0, "labels": ["documentation", "good first issue"]},
    ]}}
    assert detect_security_signals(metrics) == []


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


def _sig(number, severity, state, comments=0):
    return {"number": number, "title": f"issue {number}", "url": "u",
            "state": state, "comments": comments, "severity": severity,
            "matched_term": "rce"}


def test_format_signal_insight_leads_with_open_actionable():
    signals = [
        _sig(1, "critical", "open"),
        _sig(2, "high", "closed"),
        _sig(3, "medium", "open"),
    ]
    out = format_signal_insight(signals)
    assert out == "3 elevated signal(s) — 1 open critical/high need attention"


def test_format_signal_insight_none_open_actionable():
    signals = [_sig(1, "critical", "closed"), _sig(2, "medium", "open")]
    out = format_signal_insight(signals)
    assert out == "2 elevated signal(s) — none open critical/high"


def test_format_signal_insight_empty():
    assert format_signal_insight([]) == "0 elevated signal(s) detected in tracked issues"


def test_detect_security_signals_flags_stale_open_high():
    metrics = {"generated_at": "2026-06-25T00:00:00Z", "related_issues": {"x": [
        {"number": 40, "title": "credential leak in build", "state": "open", "url": "u",
         "comments": 1, "updated_at": "2026-06-01T00:00:00Z"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["stale"] is True
    assert signals[0]["age_days"] == 24


def test_detect_security_signals_recent_high_not_stale():
    metrics = {"generated_at": "2026-06-25T00:00:00Z", "related_issues": {"x": [
        {"number": 41, "title": "credential leak in build", "state": "open", "url": "u",
         "comments": 1, "updated_at": "2026-06-20T00:00:00Z"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["stale"] is False


def test_detect_security_signals_closed_never_stale():
    metrics = {"generated_at": "2026-06-25T00:00:00Z", "related_issues": {"x": [
        {"number": 42, "title": "credential leak in build", "state": "closed", "url": "u",
         "comments": 1, "updated_at": "2026-01-01T00:00:00Z"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["stale"] is False


def test_detect_security_signals_medium_not_stale():
    metrics = {"generated_at": "2026-06-25T00:00:00Z", "related_issues": {"x": [
        {"number": 43, "title": "password handling cleanup", "state": "open", "url": "u",
         "comments": 0, "updated_at": "2026-01-01T00:00:00Z"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["severity"] == "medium"
    assert signals[0]["stale"] is False


def test_detect_security_signals_missing_updated_at_not_stale():
    metrics = {"generated_at": "2026-06-25T00:00:00Z", "related_issues": {"x": [
        {"number": 44, "title": "credential leak in build", "state": "open", "url": "u",
         "comments": 0},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["age_days"] is None
    assert signals[0]["stale"] is False


def test_format_security_signals_marks_stale():
    signals = [
        {"number": 1, "title": "credential leak", "url": "u", "state": "open",
         "comments": 2, "severity": "high", "matched_term": "credential leak",
         "stale": True, "age_days": 30},
    ]
    out = format_security_signals(signals)
    assert "⚠️ 1 stale" in out
    assert "⚠️ stale 30d" in out


def test_format_signal_insight_reports_stale_count():
    signals = [
        {**_sig(1, "critical", "open"), "stale": True, "age_days": 20},
        {**_sig(2, "high", "open"), "stale": False, "age_days": 2},
    ]
    out = format_signal_insight(signals)
    assert out == "2 elevated signal(s) — 2 open critical/high need attention (1 stale >14d)"


def test_detect_security_signals_stale_ranks_before_fresh_within_severity():
    metrics = {"generated_at": "2026-06-25T00:00:00Z", "related_issues": {"x": [
        {"number": 50, "title": "credential leak in app", "state": "open", "url": "u",
         "comments": 9, "updated_at": "2026-06-24T00:00:00Z"},
        {"number": 51, "title": "credential leak in build", "state": "open", "url": "u",
         "comments": 0, "updated_at": "2026-05-01T00:00:00Z"},
    ]}}
    signals = detect_security_signals(metrics)
    assert [s["number"] for s in signals] == [51, 50]
    assert signals[0]["stale"] is True and signals[1]["stale"] is False


def test_detect_security_signals_open_still_outranks_stale_closed():
    metrics = {"generated_at": "2026-06-25T00:00:00Z", "related_issues": {"x": [
        {"number": 60, "title": "credential leak in logs", "state": "closed", "url": "u",
         "comments": 9, "updated_at": "2026-01-01T00:00:00Z"},
        {"number": 61, "title": "credential leak in build", "state": "open", "url": "u",
         "comments": 0, "updated_at": "2026-06-24T00:00:00Z"},
    ]}}
    signals = detect_security_signals(metrics)
    assert [s["number"] for s in signals] == [61, 60]


@pytest.mark.parametrize("text,expected", [
    ("Fixes CVE-2024-1234 in parser", ["CVE-2024-1234"]),
    ("cve-2023-99999 lowercase", ["CVE-2023-99999"]),
    ("CVE-2024-0001 and CVE-2024-0002", ["CVE-2024-0001", "CVE-2024-0002"]),
    ("dup CVE-2024-1111 then CVE-2024-1111", ["CVE-2024-1111"]),
    ("no identifier here", []),
    ("malformed CVE-24-1 ignored", []),
    ("", []),
])
def test_extract_cve_ids(text, expected):
    assert extract_cve_ids(text) == expected


def test_extract_cve_ids_across_multiple_texts_preserves_first_seen_order():
    assert extract_cve_ids("body mentions CVE-2024-2000", "title CVE-2024-1000") == [
        "CVE-2024-2000",
        "CVE-2024-1000",
    ]


def test_detect_security_signals_captures_cve_ids():
    metrics = {"related_issues": {"cve": [
        {"number": 70, "title": "RCE via CVE-2024-4321", "state": "open", "url": "u",
         "comments": 3, "body": "also affects CVE-2024-9999"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["cve_ids"] == ["CVE-2024-4321", "CVE-2024-9999"]


def test_detect_security_signals_no_cve_ids_when_absent():
    metrics = {"related_issues": {"secret": [
        {"number": 71, "title": "Exposed secret in logs", "state": "open", "url": "u",
         "comments": 1},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["cve_ids"] == []


def test_format_security_signals_shows_cve_ids_and_count():
    signals = [
        {"number": 70, "title": "RCE issue", "url": "u", "state": "open", "comments": 3,
         "severity": "high", "matched_term": "cve-", "matched_in": "title",
         "cve_ids": ["CVE-2024-4321"], "stale": False, "age_days": 1},
    ]
    out = format_security_signals(signals)
    assert "🆔 CVE-2024-4321" in out
    assert "🆔 1 CVE(s)" in out


@pytest.mark.parametrize("text,expected", [
    ("See GHSA-j828-28rj-hfhp for details", ["GHSA-j828-28rj-hfhp"]),
    ("upper GHSA-GPV5-7X3G-GHJV normalized", ["GHSA-gpv5-7x3g-ghjv"]),
    ("GHSA-v2p6-4mp7-3r9v and GHSA-37ch-88jc-xwx2", ["GHSA-v2p6-4mp7-3r9v", "GHSA-37ch-88jc-xwx2"]),
    ("dup GHSA-j828-28rj-hfhp then GHSA-j828-28rj-hfhp", ["GHSA-j828-28rj-hfhp"]),
    ("no identifier here", []),
    ("malformed GHSA-12-34-56 ignored", []),
    ("GHSA-zzzz-1111-2222 bad charset ignored", []),
    ("", []),
])
def test_extract_ghsa_ids(text, expected):
    assert extract_ghsa_ids(text) == expected


def test_extract_ghsa_ids_across_multiple_texts_preserves_first_seen_order():
    assert extract_ghsa_ids("body GHSA-v2p6-4mp7-3r9v", "title GHSA-j828-28rj-hfhp") == [
        "GHSA-v2p6-4mp7-3r9v",
        "GHSA-j828-28rj-hfhp",
    ]


def test_detect_security_signals_captures_ghsa_ids_with_no_cve():
    metrics = {"related_issues": {"advisory": [
        {"number": 80, "title": "Advisory GHSA-j828-28rj-hfhp in dependency", "state": "open",
         "url": "u", "comments": 2, "body": "no CVE assigned yet"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["severity"] == "high"
    assert signals[0]["ghsa_ids"] == ["GHSA-j828-28rj-hfhp"]
    assert signals[0]["cve_ids"] == []


def test_format_security_signals_shows_ghsa_ids_and_count():
    signals = [
        {"number": 80, "title": "Advisory issue", "url": "u", "state": "open", "comments": 2,
         "severity": "high", "matched_term": "ghsa-", "matched_in": "title",
         "cve_ids": [], "ghsa_ids": ["GHSA-j828-28rj-hfhp"], "stale": False, "age_days": 1},
    ]
    out = format_security_signals(signals)
    assert "📛 GHSA-j828-28rj-hfhp" in out
    assert "📛 1 GHSA(s)" in out


@pytest.mark.parametrize("text,expected", [
    ("Hardcoded creds CWE-798", ["CWE-798"]),
    ("cwe-259 lowercase", ["CWE-259"]),
    ("CWE-79 and CWE-89", ["CWE-79", "CWE-89"]),
    ("dup CWE-522 then CWE-522", ["CWE-522"]),
    ("no identifier here", []),
    ("bare CWE- ignored", []),
    ("embedded MCWE-12 and CWEabc ignored", []),
    ("", []),
])
def test_extract_cwe_ids(text, expected):
    assert extract_cwe_ids(text) == expected


def test_extract_cwe_ids_across_multiple_texts_preserves_first_seen_order():
    assert extract_cwe_ids("body CWE-522", "title CWE-798") == [
        "CWE-522",
        "CWE-798",
    ]


def test_detect_security_signals_captures_cwe_ids():
    metrics = {"related_issues": {"credential": [
        {"number": 90, "title": "Hardcoded credential CWE-798", "state": "open",
         "url": "u", "comments": 4, "body": "also CWE-522 insufficiently protected"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["cwe_ids"] == ["CWE-798", "CWE-522"]


def test_format_security_signals_shows_cwe_ids_and_count():
    signals = [
        {"number": 90, "title": "Credential issue", "url": "u", "state": "open", "comments": 4,
         "severity": "high", "matched_term": "credential", "matched_in": "title",
         "cve_ids": [], "ghsa_ids": [], "cwe_ids": ["CWE-798"], "stale": False, "age_days": 1},
    ]
    out = format_security_signals(signals)
    assert "🧬 CWE-798" in out
    assert "🧬 1 CWE(s)" in out


@pytest.mark.parametrize("text,expected", [
    ("Reported as MAL-2026-2144", ["MAL-2026-2144"]),
    ("mal-2025-7 lowercase", ["MAL-2025-7"]),
    ("MAL-2026-2144 aliases MAL-2026-9", ["MAL-2026-2144", "MAL-2026-9"]),
    ("dup MAL-2026-2144 then MAL-2026-2144", ["MAL-2026-2144"]),
    ("no identifier here", []),
    ("bare MAL-2026 without sequence ignored", []),
    ("malware and malformed and malicious ignored", []),
    ("", []),
])
def test_extract_mal_ids(text, expected):
    assert extract_mal_ids(text) == expected


def test_extract_mal_ids_across_multiple_texts_preserves_first_seen_order():
    assert extract_mal_ids("body MAL-2026-9", "title MAL-2025-1") == [
        "MAL-2026-9",
        "MAL-2025-1",
    ]


def test_detect_security_signals_captures_mal_ids_with_no_other_keyword():
    metrics = {"related_issues": {"dependency": [
        {"number": 91, "title": "Advisory MAL-2026-2144 filed", "state": "open",
         "url": "u", "comments": 2, "body": "flagged in the OSV feed"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["severity"] == "critical"
    assert signals[0]["mal_ids"] == ["MAL-2026-2144"]


def test_detect_security_signals_malware_word_is_not_a_mal_advisory():
    metrics = {"related_issues": {"dependency": [
        {"number": 92, "title": "malware scanner false positive", "state": "open",
         "url": "u", "comments": 1, "body": "the malformed manifest triggered it"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals == []


def test_format_security_signals_shows_mal_ids_and_count():
    signals = [
        {"number": 91, "title": "Malicious dependency", "url": "u", "state": "open", "comments": 2,
         "severity": "critical", "matched_term": "mal-", "matched_in": "title",
         "cve_ids": [], "ghsa_ids": [], "cwe_ids": [], "mal_ids": ["MAL-2026-2144"],
         "stale": False, "age_days": 1},
    ]
    out = format_security_signals(signals)
    assert "🦠 MAL-2026-2144" in out
    assert "🦠 1 MAL(s)" in out


@pytest.mark.parametrize("text,expected", [
    ("Advisory PYSEC-2026-188 filed", ["PYSEC-2026-188"]),
    ("pysec-2026-3 lowercase", ["PYSEC-2026-3"]),
    ("PYSEC-2026-188 aliases PYSEC-2026-3", ["PYSEC-2026-188", "PYSEC-2026-3"]),
    ("dup PYSEC-2026-87 then PYSEC-2026-87", ["PYSEC-2026-87"]),
    ("no identifier here", []),
    ("bare PYSEC-2026 without sequence ignored", []),
    ("", []),
])
def test_extract_pysec_ids(text, expected):
    assert extract_pysec_ids(text) == expected


def test_extract_pysec_ids_across_multiple_texts_preserves_first_seen_order():
    assert extract_pysec_ids("body PYSEC-2026-9", "title PYSEC-2025-1") == [
        "PYSEC-2026-9",
        "PYSEC-2025-1",
    ]


def test_detect_security_signals_captures_pysec_ids_with_no_other_keyword():
    metrics = {"related_issues": {"dependency": [
        {"number": 93, "title": "Advisory PYSEC-2026-188 filed", "state": "open",
         "url": "u", "comments": 2, "body": "surfaced in the OSV feed"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["severity"] == "high"
    assert signals[0]["pysec_ids"] == ["PYSEC-2026-188"]


def test_format_security_signals_shows_pysec_ids_and_count():
    signals = [
        {"number": 93, "title": "PyPI advisory", "url": "u", "state": "open", "comments": 2,
         "severity": "high", "matched_term": "pysec-", "matched_in": "title",
         "cve_ids": [], "ghsa_ids": [], "cwe_ids": [], "mal_ids": [],
         "pysec_ids": ["PYSEC-2026-188"], "stale": False, "age_days": 1},
    ]
    out = format_security_signals(signals)
    assert "🐍 PYSEC-2026-188" in out
    assert "🐍 1 PYSEC(s)" in out


@pytest.mark.parametrize("text,expected", [
    ("Advisory RUSTSEC-2021-0125 filed", ["RUSTSEC-2021-0125"]),
    ("rustsec-2018-0001 lowercase", ["RUSTSEC-2018-0001"]),
    ("RUSTSEC-2021-0125 and RUSTSEC-2018-0001", ["RUSTSEC-2021-0125", "RUSTSEC-2018-0001"]),
    ("dup RUSTSEC-2021-0125 then RUSTSEC-2021-0125", ["RUSTSEC-2021-0125"]),
    ("no identifier here", []),
    ("bare RUSTSEC-2021 without sequence ignored", []),
    ("short RUSTSEC-2021-12 ignored", []),
    ("", []),
])
def test_extract_rustsec_ids(text, expected):
    assert extract_rustsec_ids(text) == expected


def test_extract_rustsec_ids_across_multiple_texts_preserves_first_seen_order():
    assert extract_rustsec_ids("body RUSTSEC-2026-0009", "title RUSTSEC-2025-0001") == [
        "RUSTSEC-2026-0009",
        "RUSTSEC-2025-0001",
    ]


def test_detect_security_signals_captures_rustsec_ids_with_no_other_keyword():
    metrics = {"related_issues": {"dependency": [
        {"number": 94, "title": "safetensors advisory RUSTSEC-2021-0125 filed", "state": "open",
         "url": "u", "comments": 2, "body": "surfaced in the crates.io feed"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["severity"] == "high"
    assert signals[0]["rustsec_ids"] == ["RUSTSEC-2021-0125"]


def test_format_security_signals_shows_rustsec_ids_and_count():
    signals = [
        {"number": 94, "title": "crates.io advisory", "url": "u", "state": "open", "comments": 2,
         "severity": "high", "matched_term": "rustsec-", "matched_in": "title",
         "cve_ids": [], "ghsa_ids": [], "cwe_ids": [], "mal_ids": [], "pysec_ids": [],
         "rustsec_ids": ["RUSTSEC-2021-0125"], "stale": False, "age_days": 1},
    ]
    out = format_security_signals(signals)
    assert "🦀 RUSTSEC-2021-0125" in out
    assert "🦀 1 RUSTSEC(s)" in out


@pytest.mark.parametrize("text,expected", [
    ("Advisory GO-2022-0322 filed", ["GO-2022-0322"]),
    ("go-2021-0113 lowercase", ["GO-2021-0113"]),
    ("GO-2022-0322 and GO-2021-0113", ["GO-2022-0322", "GO-2021-0113"]),
    ("dup GO-2022-0322 then GO-2022-0322", ["GO-2022-0322"]),
    ("no identifier here", []),
    ("go-live plan for go-to-market", []),
    ("logo-2024-0001 and argo-2024-0001 lookalikes", []),
    ("bare GO-2022 without sequence ignored", []),
    ("short GO-2022-12 ignored", []),
    ("", []),
])
def test_extract_go_ids(text, expected):
    assert extract_go_ids(text) == expected


def test_extract_go_ids_across_multiple_texts_preserves_first_seen_order():
    assert extract_go_ids("body GO-2026-0009", "title GO-2025-0001") == [
        "GO-2026-0009",
        "GO-2025-0001",
    ]


def test_detect_security_signals_captures_go_ids_with_no_other_keyword():
    metrics = {"related_issues": {"dependency": [
        {"number": 71, "title": "ollama advisory GO-2022-0322 filed", "state": "open",
         "url": "u", "comments": 2, "body": "surfaced in the pkg.go.dev/vuln feed"},
    ]}}
    signals = detect_security_signals(metrics)
    assert signals[0]["severity"] == "high"
    assert signals[0]["go_ids"] == ["GO-2022-0322"]
    assert signals[0]["matched_in"] == "title"


def test_detect_security_signals_go_live_phrase_not_flagged():
    metrics = {"related_issues": {"roadmap": [
        {"number": 72, "title": "plan go-live for the go-to dashboard", "state": "open",
         "url": "u", "comments": 0, "body": "no advisory here"},
    ]}}
    assert detect_security_signals(metrics) == []


def test_format_security_signals_shows_go_ids_and_count():
    signals = [
        {"number": 71, "title": "go module advisory", "url": "u", "state": "open", "comments": 2,
         "severity": "high", "matched_term": "GO-2022-0322", "matched_in": "title",
         "cve_ids": [], "ghsa_ids": [], "cwe_ids": [], "mal_ids": [], "pysec_ids": [],
         "rustsec_ids": [], "go_ids": ["GO-2022-0322"], "stale": False, "age_days": 1},
    ]
    out = format_security_signals(signals)
    assert "🐹 GO-2022-0322" in out
    assert "🐹 1 GO(s)" in out
