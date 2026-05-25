# Credential Guard Tracker

Automated daily ecosystem tracking for credential-guard plugin and security initiatives in Claude Code.

Inspired by [Big Model Radar](https://github.com/gsscsd/big_model_radar), but focused on **credential protection** and **security hardening** for AI CLI tools.

## What It Does

🤖 **Daily automated workflow** (runs at 08:00 UTC):
- Monitors credential-guard PR #62099 status & metrics
- Tracks adoption, community mentions, and related security PRs
- Scans for credential-related issues across AI CLI ecosystems
- Publishes bilingual English daily digests as GitHub Issues
- Generates weekly rollup reports with trend analysis

## Tracked Metrics

| Metric | Source | Updated |
|--------|--------|---------|
| PR Status | GitHub API | Daily |
| Citation Count | Big Model Radar, GitHub mentions | Daily |
| Related Security Issues | Claude Code, Gemini CLI, OpenAI Codex repos | Daily |
| Community Engagement | PR comments, reactions, stars | Daily |
| Plugin Adoption | GitHub stars, fork count | Daily |
| Security Vulnerabilities | Related to credential leakage | Daily |

## Reports

### Daily Digest
- Published as GitHub Issues (tags: `daily-report`)
- Snapshot of metric changes in last 24h
- Flagged items requiring attention
- **Published:** Every day at 08:15 UTC

### Weekly Rollup
- Published as GitHub Issues (tags: `weekly-report`)
- Trend analysis (7-day window)
- Community highlights & contributions
- Recommendations for next steps
- **Published:** Every Monday at 09:00 UTC

### Monthly Analysis
- Deep-dive into ecosystem trends
- Comparative analysis: credential-guard vs. other security initiatives
- Impact metrics & adoption curve
- **Published:** 1st of month at 10:00 UTC

## Tracked Repositories

### Primary
- [anthropics/claude-code](https://github.com/anthropics/claude-code) — credential-guard plugin source

### Related Security Work
- [anthropics/claude-code-action](https://github.com/anthropics/claude-code-action) — CI/CD integration
- [google-gemini/gemini-cli](https://github.com/google-gemini/gemini-cli) — Competitive security initiatives
- [openai/codex](https://github.com/openai/codex) — AI CLI tool ecosystem
- [github/copilot-cli](https://github.com/github/copilot-cli) — Related security features

## Example Daily Report

```
================================================================================
  Daily Credential Guard Tracker Report
  2026-05-26 | 24h Summary
================================================================================

[📊 METRICS SNAPSHOT]

PR Status
  └─ #62099 (credential-guard plugin)
     • State: Open
     • Comments: 3 ↑
     • Reviews: 0
     • Commits: 2 (latest: bb6d9fb)

Community Engagement
  ├─ Big Model Radar citations: 2 reports
  ├─ GitHub mentions: 12 new
  └─ Stars: 284 (↑8 from yesterday)

Related Security Activity
  ├─ Claude Code: 3 credential-related issues
  ├─ Gemini CLI: 1 similar security feature request
  └─ OpenAI Codex: No new mentions

[🔔 HIGHLIGHTS]

✅ Featured in 2 automated ecosystem reports (gsscsd, ivanweng2077)
✅ 35 passing unit tests, 100% coverage
⚠️  Awaiting maintainer review (expected within 5-7 days based on patterns)
✅ No security concerns in code review
✅ Marketplace.json entry confirmed

[💡 INSIGHTS]

• Credential protection is trending across AI CLI ecosystem
• Similar initiatives noted in Gemini CLI, GitHub Copilot security roadmap
• Enterprise demand for "secrets-before-disk" validation growing
• Current approach aligns with industry standards (GitHub Actions, Kubernetes)

[🎯 NEXT STEPS]

1. Monitor for maintainer feedback on PR
2. Prepare documentation updates if requested
3. Consider adding NotebookEdit tests (currently passing)
4. Track adoption once merged

================================================================================
```

## Setup

### 1. Create Repo

```bash
git init credential-guard-tracker
cd credential-guard-tracker
git remote add origin https://github.com/ppradyoth/credential-guard-tracker
```

### 2. Configure GitHub Actions

The workflow (`.github/workflows/daily-report.yml`) runs automatically. To trigger manually:

```bash
gh workflow run daily-report.yml
```

### 3. View Reports

Reports are published as GitHub Issues with labels:
- `daily-report` — 24h snapshots
- `weekly-report` — 7-day trends
- `monthly-report` — 30-day deep dives

Filter by label in **Issues** tab.

## Tech Stack

- **Automation:** GitHub Actions (Python 3.8+)
- **Data Source:** GitHub REST API v3
- **Storage:** GitHub Issues (immutable, searchable)
- **Reports:** Markdown (rendered in Issues)
- **Archival:** Automated cleanup (30-day retention)

## Files

```
credential-guard-tracker/
├── README.md                           # This file
├── manifest.json                        # Tracked repositories & metrics config
├── .github/workflows/
│   ├── daily-report.yml                # Runs at 08:00 UTC
│   ├── weekly-report.yml               # Runs Mondays at 09:00 UTC
│   └── monthly-report.yml              # Runs 1st of month at 10:00 UTC
├── scripts/
│   ├── fetch_metrics.py                # Gather data from GitHub APIs
│   ├── generate_report.py              # Format report markdown
│   ├── post_issue.py                   # Publish to GitHub Issues
│   └── utils.py                        # Helpers (API calls, time formatting)
└── reports/                            # Archived report markdown (for reference)
    └── 2026-05-26-daily.md
```

## Configuration

Edit `manifest.json` to customize:

```json
{
  "primary_repo": {
    "owner": "anthropics",
    "repo": "claude-code",
    "pr_number": 62099
  },
  "report_schedule": {
    "daily": "08:00 UTC",
    "weekly": "09:00 UTC (Mondays)",
    "monthly": "10:00 UTC (1st)"
  },
  "tracked_keywords": [
    "credential",
    "secret",
    "api_key",
    "hardcoded",
    "security"
  ]
}
```

## License

MIT — Use freely for your own tracking systems.

## See Also

- [Big Model Radar](https://github.com/gsscsd/big_model_radar) — Multilingual AI CLI ecosystem tracking
- [credential-guard](https://github.com/anthropics/claude-code/pull/62099) — The plugin being tracked
- [Akrivon AI](https://github.com/ppradyoth/akrivon-ai) — Related red-teaming work
