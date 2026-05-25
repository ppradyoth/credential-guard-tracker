# Quick Setup Guide

## Create the Repository

```bash
# Create repo on GitHub
gh repo create credential-guard-tracker --public --source=. --remote=origin --push

# Or initialize locally first
git init
git branch -M main
git add .
git commit -m "Initial commit: credential-guard ecosystem tracker"
git remote add origin https://github.com/ppradyoth/credential-guard-tracker
git push -u origin main
```

## Enable GitHub Actions

1. Go to your repo settings
2. Enable **Issues** (for automated issue creation)
3. Go to **Actions** → **General**
4. Ensure "Allow GitHub Actions to create and approve pull requests" is enabled

## Test Locally

```bash
# Install dependencies
pip install requests

# Fetch metrics
export GITHUB_TOKEN=<your_github_token>
python scripts/fetch_metrics.py > /tmp/test_metrics.json

# Generate report
python scripts/generate_report.py /tmp/test_metrics.json
```

## Manually Trigger First Run

```bash
gh workflow run daily-report.yml --repo ppradyoth/credential-guard-tracker
```

## Verify

- Check **Issues** tab for the automatically created daily report
- Check **Actions** tab for workflow run details
- Check `reports/` folder for archived markdown files

## Customize

Edit `manifest.json` to:
- Change tracked repositories
- Adjust report schedule times
- Add/remove search keywords
- Modify metric collection logic
