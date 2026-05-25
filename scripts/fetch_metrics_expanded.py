#!/usr/bin/env python3
"""
Expanded metrics collection for comprehensive AI CLI ecosystem security tracking.

Tracks credential-guard plugin and related security initiatives across:
- 7 AI CLI tools (Claude Code, OpenAI Codex, Gemini, Copilot, Kimi, OpenCode, Qwen)
- Security plugins and frameworks
- Agent orchestration frameworks
- Related security repositories
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, Any, List

import requests


class GitHubAPI:
    """GitHub REST API v3 wrapper."""

    def __init__(self, token: str = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({"Authorization": f"token {self.token}"})
        self.base_url = "https://api.github.com"

    def get_repo(self, owner: str, repo: str) -> Dict[str, Any]:
        """Get repository details."""
        url = f"{self.base_url}/repos/{owner}/{repo}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def search_issues(self, query: str) -> List[Dict]:
        """Search for issues/PRs."""
        url = f"{self.base_url}/search/issues"
        resp = self.session.get(url, params={"q": query, "per_page": 30})
        resp.raise_for_status()
        return resp.json().get("items", [])


def collect_repo_metrics(gh: GitHubAPI, owner: str, repo: str) -> Dict[str, Any]:
    """Collect comprehensive metrics for a repository."""
    try:
        repo_data = gh.get_repo(owner, repo)
        return {
            "name": repo_data["name"],
            "full_name": repo_data["full_name"],
            "url": repo_data["html_url"],
            "description": repo_data["description"],
            "stars": repo_data["stargazers_count"],
            "forks": repo_data["forks_count"],
            "watchers": repo_data["watchers_count"],
            "open_issues": repo_data["open_issues_count"],
            "language": repo_data["language"],
            "pushed_at": repo_data["pushed_at"],
        }
    except Exception as e:
        sys.stderr.write(f"Error fetching {owner}/{repo}: {e}\n")
        return None


def search_security_issues(gh: GitHubAPI, repo_full_name: str, keywords: List[str]) -> Dict[str, list]:
    """Search for security-related issues across all repositories."""
    results = {}

    for keyword in keywords[:8]:  # Limit to reduce rate limiting
        try:
            query = f"{keyword} repo:{repo_full_name}"
            issues = gh.search_issues(query)
            results[keyword] = [
                {
                    "number": issue["number"],
                    "title": issue["title"],
                    "state": issue["state"],
                    "url": issue["html_url"],
                    "created_at": issue["created_at"],
                    "comments": issue["comments"],
                }
                for issue in issues[:3]
            ]
        except Exception as e:
            sys.stderr.write(f"Error searching {keyword} in {repo_full_name}: {e}\n")
            continue

    return results


def format_timestamp() -> str:
    """Get ISO 8601 timestamp."""
    return datetime.utcnow().isoformat() + "Z"


def main():
    """Main entry point."""
    with open("manifest-expanded.json", "r") as f:
        manifest = json.load(f)

    gh = GitHubAPI()

    metrics = {
        "generated_at": format_timestamp(),
        "scope": "Comprehensive AI CLI ecosystem security tracking",
        "primary_pr": None,
        "ai_cli_tools": {},
        "security_initiatives": {},
        "ecosystem_overview": None,
    }

    sys.stderr.write("=== Credential Guard Tracker — Expanded Metrics ===\n")

    # Primary PR
    sys.stderr.write("Fetching primary PR (credential-guard)...\n")
    try:
        pr_owner = manifest["tracking"]["primary_pr"]["owner"]
        pr_repo = manifest["tracking"]["primary_pr"]["repo"]
        pr_number = manifest["tracking"]["primary_pr"]["pr_number"]

        endpoint = f"/repos/{pr_owner}/{pr_repo}/pulls/{pr_number}"
        resp = gh.session.get(f"{gh.base_url}{endpoint}")
        resp.raise_for_status()
        pr = resp.json()

        metrics["primary_pr"] = {
            "number": pr["number"],
            "state": pr["state"],
            "title": pr["title"],
            "url": pr["html_url"],
            "comments": pr["comments"],
            "created_at": pr["created_at"],
            "updated_at": pr["updated_at"],
        }
    except Exception as e:
        sys.stderr.write(f"Error fetching primary PR: {e}\n")

    # AI CLI Tools
    sys.stderr.write("\nFetching AI CLI tool metrics...\n")
    for tool in manifest["tracking"]["ai_cli_tools"]:
        sys.stderr.write(f"  • {tool['name']} ({tool['owner']}/{tool['repo']})\n")
        repo_data = collect_repo_metrics(gh, tool["owner"], tool["repo"])
        if repo_data:
            metrics["ai_cli_tools"][tool["name"]] = {
                "repo": repo_data,
                "security_issues": search_security_issues(
                    gh,
                    f"{tool['owner']}/{tool['repo']}",
                    manifest["keywords_and_patterns"]["credential_keywords"][:5]
                ),
            }

    # Security Plugins
    sys.stderr.write("\nFetching security plugin metrics...\n")
    for plugin in manifest["tracking"]["security_plugins"]:
        sys.stderr.write(f"  • {plugin['name']}\n")
        repo_data = collect_repo_metrics(gh, plugin["owner"], plugin["repo"])
        if repo_data:
            metrics["security_initiatives"][plugin["name"]] = repo_data

    # Agent Frameworks
    sys.stderr.write("\nFetching agent framework metrics...\n")
    for framework in manifest["tracking"]["agent_frameworks"]:
        sys.stderr.write(f"  • {framework['name']}\n")
        repo_data = collect_repo_metrics(gh, framework["owner"], framework["repo"])
        if repo_data:
            metrics["security_initiatives"][f"{framework['name']} (Agent)"] = repo_data

    # Ecosystem Overview
    sys.stderr.write("\nCompiling ecosystem overview...\n")
    cli_stars = sum(t.get("repo", {}).get("stars", 0) for t in metrics["ai_cli_tools"].values())
    total_repos = len(metrics["ai_cli_tools"]) + len(metrics["security_initiatives"])

    metrics["ecosystem_overview"] = {
        "ai_cli_tools_tracked": len(manifest["tracking"]["ai_cli_tools"]),
        "security_initiatives_tracked": len(manifest["tracking"]["security_plugins"]) + len(manifest["tracking"]["agent_frameworks"]),
        "total_repos_monitored": total_repos,
        "combined_stars": cli_stars,
        "security_focus_areas": manifest["keywords_and_patterns"]["credential_keywords"],
    }

    # Output JSON to stdout
    sys.stdout.write(json.dumps(metrics, indent=2))
    sys.stdout.write("\n")
    sys.stderr.write("\n✅ Metrics collection complete\n")

    return metrics


if __name__ == "__main__":
    main()
