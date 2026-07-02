# Credential Guard Tracker

[![Tests](https://github.com/ppradyoth/credential-guard-tracker/actions/workflows/tests.yml/badge.svg)](https://github.com/ppradyoth/credential-guard-tracker/actions/workflows/tests.yml)
[![Daily Report](https://github.com/ppradyoth/credential-guard-tracker/actions/workflows/daily-report.yml/badge.svg)](https://github.com/ppradyoth/credential-guard-tracker/actions/workflows/daily-report.yml)
![Python](https://img.shields.io/badge/python-3.11-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Automated daily ecosystem tracking for credential-guard plugin and security initiatives in Claude Code.

**Keywords:** credential security · AI supply chain security · secrets detection · LLM tool hardening · Claude Code plugins

Inspired by [Big Model Radar](https://github.com/gsscsd/big_model_radar), but focused on **credential protection** and **security hardening** for AI CLI tools.

## What It Does

🤖 **Daily automated workflow** (runs at 08:00 UTC):
- Monitors credential-guard PR #62099 status & metrics
- Tracks adoption, community mentions, and related security PRs
- Scans for credential-related issues across AI CLI ecosystems
- **Detects and ranks security signals** in tracked issues by severity (critical / high / medium)
- Publishes bilingual English daily digests as GitHub Issues
- Generates weekly rollup reports with trend analysis

## 🔐 Security Signal Detection

Every daily report runs a keyword-tiered classifier over the tracked issues and
surfaces the highest-risk ones first — so credential leaks and supply-chain risks
don't get buried in routine noise. Both the **issue title and body** are scanned
(highest severity across the two wins, title preferred on ties), so a risk buried
in a long write-up is still caught. Keyword matching is **word-boundary anchored**,
so short acronyms like `rce` flag a genuine "Possible RCE in parser" without
false-positiving on unrelated words such as `source`, `resource`, or `enforce`.
Multi-word signals are **separator-flexible**: the space inside a term like
`supply chain` or `remote code execution` matches hyphens and line wraps too, so
`supply-chain` and a body-wrapped `exposed\nsecret` are caught all the same.
Ranking is **actionable-first**: signals sort by severity, then open-before-closed
(an open issue is still live and worth triaging), then by comment activity — so an
open critical never sits below an already-closed one. The **Key Insights** line
leads with that actionable count — how many critical/high signals are still
**open** — rather than a raw total, so the headline is what needs attention today
(e.g. `3 elevated signal(s) — 1 open critical/high need attention`).
Each signal is tagged with the matched term, where it matched, and its severity:

```text
## 🔐 Security Signals

**3 signal(s)** — 🟥 0 critical · 🟧 1 high · 🟨 2 medium

  🟧 **HIGH** 🔵 [#222](https://github.com/anthropics/claude-code/issues/222) — Supply chain risk: unpinned action exfiltrates token
     • matched `supply chain` in title | 12 comments
  🟨 **MEDIUM** 🔵 [#100](https://github.com/anthropics/claude-code/issues/100) — Refactor token cache
     • matched `credential` in body | 5 comments
```

Severity tiers are defined in `scripts/generate_report.py` (`_SECURITY_SIGNAL_PATTERNS`)
and are fully unit-tested. This is the kind of triage signal that makes the tracker
useful as **AI supply-chain security tooling**, not just a metrics dashboard.

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

## Testing

The metric-collection and report-generation logic is covered by a unit test suite
(no network or GitHub token required — API responses are stubbed):

```bash
pip install pytest requests
pytest -q
```

Tests run automatically on every push and pull request via the
[Tests workflow](.github/workflows/tests.yml).

## License

MIT — Use freely for your own tracking systems.

## See Also

- [Big Model Radar](https://github.com/gsscsd/big_model_radar) — Multilingual AI CLI ecosystem tracking
- [credential-guard](https://github.com/anthropics/claude-code/pull/62099) — The plugin being tracked

---

Maintained with [Claude Code](https://claude.ai/code) — see the [autonomous agent experiment](https://github.com/ppradyoth/social-experiment-with-agents).
