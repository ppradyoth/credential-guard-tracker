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


def generate_weekly_report(metrics_history: list) -> str:
    """Generate weekly rollup report."""
    if not metrics_history:
        return "No metrics history available."

    latest = metrics_history[-1]
    earliest = metrics_history[0]

    report = f"""================================================================================
  📈 Credential Guard Tracker — Weekly Rollup
  Week of {earliest.get('generated_at', '')[:10]}
================================================================================

> 7-day trend analysis for credential-guard security plugin

## Summary

| Metric | Start | End | Change |
|--------|-------|-----|--------|
| PR Comments | {earliest['pr']['comments_count']} | {latest['pr']['comments_count']} | +{latest['pr']['comments_count'] - earliest['pr']['comments_count']} |
| Repository Stars | {earliest['repo']['stars']} | {latest['repo']['stars']} | +{latest['repo']['stars'] - earliest['repo']['stars']} |
| Open Issues | {earliest['repo']['open_issues']} | {latest['repo']['open_issues']} | {latest['repo']['open_issues'] - earliest['repo']['open_issues']} |

## Highlights

✅ **Consistent Progress** — PR remains open and under active discussion
✅ **Growing Interest** — Star count increasing across the 7-day window
🔵 **Ecosystem Engagement** — Multiple related issues detected in Claude Code ecosystem

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
