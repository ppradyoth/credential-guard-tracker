import copy

import pytest
from conftest import SAMPLE_METRICS

from generate_report import (
    format_pr_status,
    format_related_issues,
    format_repo_stats,
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
