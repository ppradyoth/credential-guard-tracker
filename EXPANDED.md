# Credential Guard Tracker — Expanded Version

Comprehensive security and credential protection tracking across the **entire AI CLI and agent ecosystem**.

Inspired by [Big Model Radar](https://github.com/gsscsd/big_model_radar) but focused specifically on **credential detection, secret protection, and security initiatives**.

## Scope

### 🛠️ AI CLI Tools (7 Tools)

| Tool | Repository | Focus |
|------|-----------|-------|
| **Claude Code** | anthropics/claude-code | Primary — credential-guard plugin |
| **OpenAI Codex** | openai/codex | Competitive security patterns |
| **Gemini CLI** | google-gemini/gemini-cli | Permission & auth security |
| **GitHub Copilot CLI** | github/copilot-cli | Credential handling |
| **Kimi Code CLI** | MoonshotAI/kimi-cli | Plugin ecosystem security |
| **OpenCode** | anomalyco/opencode | Credential protection |
| **Qwen Code** | QwenLM/qwen-code | Data security & telemetry |

### 🔒 Security & Plugins

- Claude Code security-guidance plugin (existing)
- Claude Code hookify plugin (custom rules)
- **credential-guard plugin** (NEW — the focus)

### 🤖 Agent Frameworks (5 Frameworks)

| Framework | Repository | Security Focus |
|-----------|-----------|-----------------|
| Claude Agent SDK | anthropics-sdk-python | Agent permission model |
| OpenClaw | openclaw/openclaw | Multi-agent credential isolation |
| Langchain | langchain-ai/langchain | Tool credential management |
| AutoGen | microsoft/autogen | Agent communication security |
| Crew AI | joaomdmoura/crewai | Multi-agent credential handling |

### 🛡️ Related Security Repos

- OWASP Top 10 (reference)
- Snyk vulnerability detection
- GitGuardian secret scanning
- Hugging Face Transformers (model security)

## Keywords Tracked

### Credential-Focused
- credential
- secret
- api_key / apikey
- password
- token
- bearer
- authentication
- oauth
- jwt
- private_key

### Security-General
- security
- hardcoded
- injection
- xss
- permission
- auth
- encrypt
- vulnerability
- exploit

## What Gets Monitored

| Metric | Coverage | Update |
|--------|----------|--------|
| **PR Status** | credential-guard #62099 | Real-time |
| **Security Issues** | All 7 CLI tools | Daily |
| **Credential Leaks** | All repos | Daily |
| **Security PRs** | All repos | Daily |
| **Plugin Adoption** | credential-guard | Daily |
| **Ecosystem Trend** | All repos | Weekly |

## Report Types

### Daily Report (08:00 UTC)
- credential-guard PR engagement
- New security issues (all repos)
- Credential-related activity
- Security PRs and merges
- Trending security keywords

### Weekly Report (Mondays 09:00 UTC)
- 7-day trends across ecosystem
- Security initiative comparison
- Tool-to-tool security feature parity
- Community contribution highlights

### Monthly Report (1st of month 10:00 UTC)
- Deep dive on security landscape
- AI CLI tool security comparison table
- Credential protection patterns
- Recommendations for next month

## Files

**Configuration:**
- `manifest.json` — Original focused version
- `manifest-expanded.json` — Comprehensive ecosystem version

**Scripts:**
- `scripts/fetch_metrics.py` — Focused tracking (credential-guard primary)
- `scripts/fetch_metrics_expanded.py` — Comprehensive ecosystem tracking

**Workflows:**
- `.github/workflows/daily-report.yml` — Primary dashboard reports
- `.github/workflows/publish-website.yml` — GitHub Pages deployment

## Key Differences: Focused vs Expanded

| Aspect | Focused | Expanded |
|--------|---------|----------|
| **Scope** | credential-guard only | Entire AI CLI ecosystem |
| **Repos Tracked** | 1 | 15+ |
| **Tools Monitored** | 1 CLI tool | 7 CLI tools + 5 agent frameworks |
| **Keywords** | 5 credential keywords | 10 credential + 10 security keywords |
| **Reports** | Daily, weekly, monthly | Same + ecosystem comparisons |
| **Comparisons** | N/A | Tool-to-tool security analysis |

## Why This Matters

### For Security Engineers
- Track credential protection trends across the ecosystem
- Monitor adoption of security patterns
- Identify security gaps across tools

### For Project Managers
- Understand ecosystem-wide security initiatives
- Benchmark credential-guard against competitors
- Plan security roadmap based on trends

### For Community
- Transparent view of security across AI tools
- Discover similar initiatives in peer projects
- Learn from security best practices

## Similar Projects

- **Big Model Radar** (gsscsd/big_model_radar) — Comprehensive AI CLI tracking (Chinese + English)
- **GitHub Trending** — AI repo trends
- **OWASP Top 10** — Web security reference

## Usage

### Using Expanded Version

```bash
# Use expanded manifest
mv manifest.json manifest-focused.json
mv manifest-expanded.json manifest.json

# Use expanded metrics script
python scripts/fetch_metrics_expanded.py > /tmp/metrics.json

# Generate reports
python scripts/generate_report.py /tmp/metrics.json
```

### Switching Back to Focused

```bash
# Revert to primary tracking
mv manifest.json manifest-expanded.json
mv manifest-focused.json manifest.json
```

## Next Steps

1. ✅ Implement expanded tracking
2. ⏳ Collect 30 days of data
3. ⏳ Generate ecosystem comparison table
4. ⏳ Publish weekly security briefing
5. ⏳ Add trend visualization to website

---

**Vision:** Be to AI CLI security what Big Model Radar is to AI CLI ecosystem — comprehensive, transparent, community-focused tracking of the security landscape.

📊 **Comprehensive. Transparent. Community-Driven.**
