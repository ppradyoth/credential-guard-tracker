#!/usr/bin/env python3
"""
Generate markdown daily/weekly/monthly reports from collected metrics.
"""

import json
import re
from datetime import datetime
from typing import Dict, Any, List


def format_pr_status(pr: Dict[str, Any]) -> str:
    """Format PR status section."""
    state_emoji = "🟢" if pr["state"] == "open" else "🟣"
    merged_emoji = "✅" if pr.get("merged_at") else ""

    lines = [
        "## PR Status",
        "",
        f"**{state_emoji} #{pr['url'].split('/')[-1]}** — {pr['title']}",
        f"  • State: {pr['state'].upper()} {merged_emoji}",
        f"  • Comments: {pr['comments_count']}",
        f"  • Reviews: {pr['review_count']}",
        f"  • Reactions: 👍 {pr['reactions'].get('thumbs_up', 0)} ❤️ {pr['reactions'].get('heart', 0)}",
        f"  • Created: {pr['created_at'][:10]}",
        f"  • Updated: {pr['updated_at'][:10]}",
        "",
    ]

    if pr["latest_comments"]:
        lines.append("### Recent Comments")
        for comment in pr["latest_comments"]:
            lines.append(
                f"  > **{comment['author']}** ({comment['created_at'][:10]}): "
                f"{comment['body']}..."
            )
        lines.append("")

    return "\n".join(lines)


def format_repo_stats(repo: Dict[str, Any]) -> str:
    """Format repository statistics."""
    lines = [
        "## Repository Stats",
        "",
        f"**{repo['full_name']}**",
        f"  • ⭐ Stars: {repo['stars']:,}",
        f"  • 🍴 Forks: {repo['forks']:,}",
        f"  • 👀 Watchers: {repo['watchers']:,}",
        f"  • 🐛 Open Issues: {repo['open_issues']}",
        f"  • 📝 Language: {repo['language'] or 'N/A'}",
        f"  • 📅 Last Updated: {repo['updated_at'][:10]}",
        "",
    ]

    if repo["topics"]:
        lines.append(f"**Topics:** {', '.join([f'`{t}`' for t in repo['topics'][:8]])}")
        lines.append("")

    return "\n".join(lines)


def format_related_issues(issues_by_keyword: Dict[str, list]) -> str:
    """Format related issues section."""
    lines = [
        "## Related Issues & Activity",
        "",
    ]

    issue_count = sum(len(v) for v in issues_by_keyword.values())
    lines.append(f"**Found {issue_count} related issues across {len(issues_by_keyword)} keywords**")
    lines.append("")

    for keyword, issues in issues_by_keyword.items():
        if issues:
            lines.append(f"### {keyword.capitalize()}")
            for issue in issues[:3]:
                status = "✅" if issue["state"] == "closed" else "🔵"
                lines.append(
                    f"  {status} [#{issue['number']}]({issue['url']}) — {issue['title']}"
                )
                lines.append(f"     • {issue['comments']} comments | {issue['created_at'][:10]}")
            lines.append("")

    return "\n".join(lines)


_SECURITY_SIGNAL_PATTERNS = [
    (
        "critical",
        [
            "exposed secret",
            "leaked credential",
            "leaked secret",
            "hardcoded secret",
            "hardcoded credential",
            "private key leak",
            "remote code execution",
            "rce",
        ],
    ),
    (
        "high",
        [
            "secret leak",
            "credential leak",
            "token leak",
            "api key",
            "apikey",
            "supply chain",
            "exfiltrat",
            "cve-",
            "arbitrary code",
        ],
    ),
    (
        "medium",
        [
            "secret",
            "credential",
            "password",
            "hardcode",
            "vulnerab",
            "injection",
            "unauthorized",
            "leak",
        ],
    ),
]

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1}
_SEVERITY_EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨"}

# Pre-compile each keyword as a word-boundary-anchored prefix match. Anchoring on
# `\b` stops short acronyms (e.g. "rce") from matching inside unrelated words
# ("source", "resource", "enforce", "commerce") while still allowing genuine
# stems ("exfiltrat" → "exfiltration", "vulnerab" → "vulnerability") to match.
# Internal spaces in multi-word terms are compiled to `[\s-]+`, so hyphenated or
# line-wrapped variants ("supply-chain", "remote-code-execution", "api\nkey")
# still match the same signal.
def _compile_signal_term(term: str) -> "re.Pattern[str]":
    return re.compile(r"\b" + r"[\s-]+".join(re.escape(part) for part in term.split(" ")))


_COMPILED_SIGNAL_PATTERNS = [
    (severity, [(term, _compile_signal_term(term)) for term in terms])
    for severity, terms in _SECURITY_SIGNAL_PATTERNS
]


def _match_severity(text: str):
    """Return the highest-severity (severity, term) matched in text, or (None, None)."""
    text = (text or "").lower()
    for severity, terms in _COMPILED_SIGNAL_PATTERNS:
        for term, pattern in terms:
            if pattern.search(text):
                return severity, term
    return None, None


def detect_security_signals(metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan tracked issues for security-risk keywords and rank by severity.

    Each issue's title and body are matched against tiered keyword patterns;
    the issue is assigned the highest-severity tier matched across both, with
    the title preferred on ties. Returns a de-duplicated list sorted by
    severity (critical first), then open-before-closed (open issues are still
    actionable), then by comment activity.
    """
    signals: Dict[int, Dict[str, Any]] = {}

    for keyword, issues in (metrics.get("related_issues") or {}).items():
        for issue in issues:
            title_sev, title_term = _match_severity(issue.get("title"))
            body_sev, body_term = _match_severity(issue.get("body"))

            if title_sev and (not body_sev or _SEVERITY_RANK[title_sev] >= _SEVERITY_RANK[body_sev]):
                matched_severity, matched_term, matched_in = title_sev, title_term, "title"
            elif body_sev:
                matched_severity, matched_term, matched_in = body_sev, body_term, "body"
            else:
                continue

            number = issue.get("number")
            existing = signals.get(number)
            if existing and _SEVERITY_RANK[existing["severity"]] >= _SEVERITY_RANK[matched_severity]:
                continue

            signals[number] = {
                "number": number,
                "title": issue.get("title", ""),
                "url": issue.get("url", ""),
                "state": issue.get("state", ""),
                "comments": issue.get("comments", 0),
                "severity": matched_severity,
                "matched_term": matched_term,
                "matched_in": matched_in,
            }

    return sorted(
        signals.values(),
        key=lambda s: (
            _SEVERITY_RANK[s["severity"]],
            0 if s["state"] == "closed" else 1,
            s["comments"],
        ),
        reverse=True,
    )


def format_security_signals(signals: List[Dict[str, Any]]) -> str:
    """Format the ranked security-signal section."""
    lines = ["## 🔐 Security Signals", ""]

    if not signals:
        lines.append("No elevated security signals detected in tracked issues.")
        lines.append("")
        return "\n".join(lines)

    counts = {"critical": 0, "high": 0, "medium": 0}
    for signal in signals:
        counts[signal["severity"]] += 1

    lines.append(
        f"**{len(signals)} signal(s)** — "
        f"🟥 {counts['critical']} critical · "
        f"🟧 {counts['high']} high · "
        f"🟨 {counts['medium']} medium"
    )
    lines.append("")

    for signal in signals:
        emoji = _SEVERITY_EMOJI[signal["severity"]]
        state = "✅" if signal["state"] == "closed" else "🔵"
        lines.append(
            f"  {emoji} **{signal['severity'].upper()}** {state} "
            f"[#{signal['number']}]({signal['url']}) — {signal['title']}"
        )
        lines.append(
            f"     • matched `{signal['matched_term']}` in {signal.get('matched_in', 'title')} "
            f"| {signal['comments']} comments"
        )
    lines.append("")

    return "\n".join(lines)


def format_signal_insight(signals: List[Dict[str, Any]]) -> str:
    """Build the Key Insights line, leading with the open critical/high count.

    The headline number for triage is how many high-severity signals are still
    open — those are what a maintainer must act on today, not the resolved ones.
    """
    total = len(signals)
    if total == 0:
        return "0 elevated signal(s) detected in tracked issues"

    open_actionable = sum(
        1
        for s in signals
        if s["state"] != "closed" and s["severity"] in ("critical", "high")
    )
    if open_actionable:
        tail = f"{open_actionable} open critical/high need attention"
    else:
        tail = "none open critical/high"
    return f"{total} elevated signal(s) — {tail}"


def generate_daily_report(metrics: Dict[str, Any]) -> str:
    """Generate daily report markdown."""
    generated = metrics.get("generated_at", "").split("T")[0]

    report = f"""================================================================================
  📊 Credential Guard Tracker — Daily Report
  {generated}
================================================================================

> Automated ecosystem tracking for credential-guard plugin (#62099)

{format_pr_status(metrics['pr'])}

{format_repo_stats(metrics['repo'])}

{format_related_issues(metrics['related_issues'])}

{format_security_signals(detect_security_signals(metrics))}

## 🎯 Key Insights

- **PR Health:** {metrics['pr']['state'].upper()} with {metrics['pr']['comments_count']} comments
- **Repository Momentum:** ⭐ {metrics['repo']['stars']:,} stars, 📊 {metrics['repo']['watchers']:,} watchers
- **Ecosystem Activity:** {sum(len(v) for v in metrics['related_issues'].values())} related issues found
- **Security Signals:** {format_signal_insight(detect_security_signals(metrics))}
- **Last Activity:** {metrics['repo']['updated_at'][:10]}

## 📌 Notes

This report is auto-generated daily. Last update: {datetime.utcnow().isoformat()}Z

---

**Links:**
- PR: {metrics['pr']['url']}
- Repo: https://github.com/{metrics['repo']['full_name']}
- Issues: {metrics['repo']['full_name']}/issues

"""

    return report


def _format_delta(delta: int) -> str:
    """Render a signed change, avoiding '+-3' for negative deltas."""
    if delta > 0:
        return f"+{delta}"
    if delta < 0:
        return str(delta)
    return "0"


def _weekly_highlights(earliest: Dict[str, Any], latest: Dict[str, Any]) -> str:
    """Build data-driven highlights from the actual start/end deltas."""
    stars_delta = latest["repo"]["stars"] - earliest["repo"]["stars"]
    comments_delta = latest["pr"]["comments_count"] - earliest["pr"]["comments_count"]
    pr_state = latest["pr"]["state"]
    issues_total = sum(len(v) for v in latest.get("related_issues", {}).values())

    lines = []

    if latest["pr"].get("merged_at"):
        lines.append("✅ **Merged** — PR landed during this window")
    elif pr_state == "open":
        lines.append("🟢 **Open** — PR remains open during this window")
    else:
        lines.append("🟣 **Closed** — PR was closed during this window")

    if comments_delta > 0:
        lines.append(f"💬 **Active Discussion** — {_format_delta(comments_delta)} comments over the window")
    elif comments_delta == 0:
        lines.append("💬 **Quiet** — no new comments over the window")

    if stars_delta > 0:
        lines.append(f"✅ **Growing Interest** — {_format_delta(stars_delta)} stars over the 7-day window")
    elif stars_delta == 0:
        lines.append("➖ **Stable Interest** — star count unchanged over the window")
    else:
        lines.append(f"🔻 **Declining Interest** — {_format_delta(stars_delta)} stars over the window")

    if issues_total > 0:
        lines.append(f"🔵 **Ecosystem Engagement** — {issues_total} related issues detected in the Claude Code ecosystem")

    return "\n".join(lines)


def generate_weekly_report(metrics_history: list) -> str:
    """Generate weekly rollup report."""
    if not metrics_history:
        return "No metrics history available."

    latest = metrics_history[-1]
    earliest = metrics_history[0]

    comments_delta = latest['pr']['comments_count'] - earliest['pr']['comments_count']
    stars_delta = latest['repo']['stars'] - earliest['repo']['stars']
    issues_delta = latest['repo']['open_issues'] - earliest['repo']['open_issues']

    report = f"""================================================================================
  📈 Credential Guard Tracker — Weekly Rollup
  Week of {earliest.get('generated_at', '')[:10]}
================================================================================

> 7-day trend analysis for credential-guard security plugin

## Summary

| Metric | Start | End | Change |
|--------|-------|-----|--------|
| PR Comments | {earliest['pr']['comments_count']} | {latest['pr']['comments_count']} | {_format_delta(comments_delta)} |
| Repository Stars | {earliest['repo']['stars']} | {latest['repo']['stars']} | {_format_delta(stars_delta)} |
| Open Issues | {earliest['repo']['open_issues']} | {latest['repo']['open_issues']} | {_format_delta(issues_delta)} |

## Highlights

{_weekly_highlights(earliest, latest)}

## Recommendations

1. Monitor for maintainer feedback on PR
2. Prepare for potential feature requests or change requests
3. Consider documentation updates based on community feedback
4. Track adoption metrics once PR is merged

---

*Report generated: {datetime.utcnow().isoformat()}Z*

"""

    return report


def main():
    """Main entry point."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: generate_report.py <metrics.json> [weekly|monthly]")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        metrics = json.load(f)

    report_type = sys.argv[2] if len(sys.argv) > 2 else "daily"

    if report_type == "weekly":
        report = generate_weekly_report([metrics])
    else:
        report = generate_daily_report(metrics)

    print(report)


if __name__ == "__main__":
    main()
