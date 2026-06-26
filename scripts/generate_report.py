#!/usr/bin/env python3
"""
Generate markdown daily/weekly/monthly reports from collected metrics.
"""

import json
from datetime import datetime
from typing import Dict, Any


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

## 🎯 Key Insights

- **PR Health:** {metrics['pr']['state'].upper()} with {metrics['pr']['comments_count']} comments
- **Repository Momentum:** ⭐ {metrics['repo']['stars']:,} stars, 📊 {metrics['repo']['watchers']:,} watchers
- **Ecosystem Activity:** {sum(len(v) for v in metrics['related_issues'].values())} related issues found
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
